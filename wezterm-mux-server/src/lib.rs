//! wezterm-mux-server library — reusable building blocks for mux daemon
//! startup. Embedding crates (e.g. termob-server) compose these blocks
//! with their own CLI + capability dispatch instead of duplicating the
//! bootstrap sequence.

use std::io::{Read, Write};
use std::rc::Rc;
use std::sync::Arc;

use mux::activity::Activity;
use mux::domain::{Domain, LocalDomain};
use mux::Mux;
use portable_pty::cmdbuilder::CommandBuilder;

pub mod daemonize;
pub mod ossl;

/// Initialize environment bootstrap (logging, crash handler, etc.) and
/// load the wezterm configuration.
///
/// Call this before any other building block.
pub fn bootstrap_config(
    config_file: Option<&std::ffi::OsString>,
    config_override: &[(String, String)],
    skip_config: bool,
) -> anyhow::Result<config::ConfigHandle> {
    env_bootstrap::bootstrap();
    config::designate_this_as_the_main_thread();

    config::common_init(config_file, config_override, skip_config)?;

    let config = config::configuration();
    config.update_ulimit()?;
    if let Some(value) = &config.default_ssh_auth_sock {
        std::env::set_var("SSH_AUTH_SOCK", value);
    }
    Ok(config)
}

/// Scrub environment variables that are misleading for a daemon process.
/// Also removes user-configured `mux_env_remove` entries.
pub fn scrub_env() {
    for name in &[
        "OLDPWD",
        "PWD",
        "SHLVL",
        "WEZTERM_PANE",
        "WEZTERM_UNIX_SOCKET",
        "_",
    ] {
        std::env::remove_var(name);
    }
    for name in &config::configuration().mux_env_remove {
        std::env::remove_var(name);
    }
}

/// Register blob lease storage in `CACHE_DIR`. Required before mux
/// operations that transfer large terminal content.
pub fn init_blob_leases() -> anyhow::Result<()> {
    wezterm_blob_leases::register_storage(Arc::new(
        wezterm_blob_leases::simple_tempdir::SimpleTempDir::new_in(&*config::CACHE_DIR)?,
    ))?;
    Ok(())
}

/// Create the mux singleton with a "local" domain and return the mux Arc.
pub fn init_mux() -> anyhow::Result<Arc<Mux>> {
    let domain: Arc<dyn Domain> = Arc::new(LocalDomain::new("local")?);
    let mux = Arc::new(Mux::new(Some(domain)));
    Mux::set_mux(&mux);
    Ok(mux)
}

/// Spawn UDS + TLS listeners from config.
///
/// `tls_verify_peer`: whether TLS connections require mTLS peer cert
/// verification.
pub fn spawn_listeners(tls_verify_peer: bool) -> anyhow::Result<()> {
    let config = config::configuration();
    for unix_dom in &config.unix_domains {
        std::env::set_var("WEZTERM_UNIX_SOCKET", unix_dom.socket_path());
        let mut listener = wezterm_mux_server_impl::local::LocalListener::with_domain(unix_dom)?;
        std::thread::spawn(move || {
            listener.run();
        });
    }

    for tls_server in &config.tls_servers {
        ossl::spawn_tls_listener(tls_server, tls_verify_peer)?;
    }

    Ok(())
}

/// Copy bytes from `from_stream` to `to_stream` in 8 KiB chunks until EOF
/// or error. This is the byte pump used by the `proxy` byte-pipe mode
/// (SSH-mux netcat over a UDS socket). Exposed from the library so that
/// embedding crates (e.g. termob-server) reuse the exact same loop instead
/// of hand-rolling it; the original lived in `wezterm/src/cli/proxy.rs` as
/// `consume_stream`. Process-exit / shutdown policy stays with the caller —
/// this function only copies and returns.
pub fn consume_stream<F: Read, T: Write>(
    mut from_stream: F,
    mut to_stream: T,
) -> anyhow::Result<()> {
    let mut buf = [0u8; 8192];

    loop {
        let size = from_stream.read(&mut buf)?;
        if size == 0 {
            break;
        }
        to_stream.write_all(&buf[0..size])?;
        to_stream.flush()?;
    }
    Ok(())
}

/// The async mux bootstrap: register domains, subscribe to config reload,
/// fire `mux-startup` Lua event, and spawn the initial pane if none exist.
pub async fn async_run_mux(cmd: Option<CommandBuilder>) -> anyhow::Result<()> {
    let mux = Mux::get();
    let config = config::configuration();

    wezterm_mux_server_impl::update_mux_domains_for_server(&config)?;

    // Config hot-reload: when the config file changes on disk, re-read
    // and update the mux domain list without restarting the server.
    let _config_subscription = config::subscribe_to_config_reload(move || {
        promise::spawn::spawn_into_main_thread(async move {
            if let Err(err) =
                wezterm_mux_server_impl::update_mux_domains_for_server(&config::configuration())
            {
                log::error!("Error updating mux domains: {:#}", err);
            }
        })
        .detach();
        true
    });

    let domain = mux.default_domain();

    // Fire `mux-startup` Lua event for user automation hooks.
    {
        if let Err(err) =
            config::with_lua_config_on_main_thread(|lua: Option<Rc<mlua::Lua>>| async move {
                if let Some(lua) = lua {
                    let args = lua.pack_multi(())?;
                    config::lua::emit_event(&lua, ("mux-startup".to_string(), args)).await?;
                }
                Ok(())
            })
            .await
        {
            log::error!("while processing mux-startup event: {:#}", err);
        }
    }

    let have_panes_in_domain = mux
        .iter_panes()
        .iter()
        .any(|p| p.domain_id() == domain.domain_id());

    if !have_panes_in_domain {
        let workspace = None;
        let position = None;
        let window_id = mux.new_empty_window(workspace, position);
        domain.attach(Some(*window_id)).await?;
        let _tab = mux
            .default_domain()
            .spawn(config.initial_size(0, None), cmd, None, *window_id)
            .await?;
    }
    Ok(())
}

/// Handle returned by [`create_executor`] and consumed by
/// [`run_executor_loop_with`]. Re-exported so embedders can name the type
/// without depending on `promise` directly.
pub use promise::spawn::SimpleExecutor;

/// Install the promise schedulers, without running the loop.
///
/// **Call this before [`spawn_listeners`] if the two are not adjacent.** A
/// listener thread calls `spawn_into_main_thread` for *every* accepted
/// connection (see `wezterm-mux-server-impl`'s `LocalListener::run`), and that
/// panics with "no scheduler has been configured" when the schedulers are not
/// installed yet. `spawn_listeners` starts those threads immediately, so a
/// client connecting before the loop starts hits the window — a readiness probe
/// that merely opens the socket is enough to trigger it. Embedders built with
/// `panic = "abort"` lose the entire process to that panic.
///
/// Creating the executor early is safe: the queue is unbounded, so work spawned
/// before [`run_executor_loop_with`] starts is not dropped — it is drained on
/// the first tick.
pub fn create_executor() -> promise::spawn::SimpleExecutor {
    promise::spawn::SimpleExecutor::new()
}

/// Spawn the async mux bootstrap as a task and run the promise executor
/// loop forever. This function never returns normally.
///
/// Installs the schedulers itself; use [`create_executor`] +
/// [`run_executor_loop_with`] when listeners must be spawned first.
pub fn run_executor_loop(cmd: Option<CommandBuilder>) -> anyhow::Result<()> {
    run_executor_loop_with(create_executor(), cmd)
}

/// [`run_executor_loop`] with an executor already built by [`create_executor`].
pub fn run_executor_loop_with(
    executor: promise::spawn::SimpleExecutor,
    cmd: Option<CommandBuilder>,
) -> anyhow::Result<()> {
    let activity = Activity::new();
    // `spawn_local_inline` enqueues the `!Send` mux bootstrap future (mux
    // `Rc<Lua>` config callbacks are `!Send`) onto the main-thread local
    // executor; it is POLLED on this thread by `executor.tick()` below (never
    // inline on a waking thread). This is the fork's dedicated entry for
    // `!Send` futures (the plain `spawn` requires `Send` because termob's
    // promise tick thread is separate). Constructing the `executor` argument
    // already installed the doorbell (see `create_executor`), so cross-thread
    // wakes (e.g. `smol::Timer`) drive the loop here.
    promise::spawn::spawn_local_inline(async move {
        if let Err(err) = async_run_mux(cmd).await {
            log::error!("{:#}; terminating", err);
            std::process::exit(1);
        }
        drop(activity);
    })
    .detach();

    loop {
        executor.tick()?;
    }
}
