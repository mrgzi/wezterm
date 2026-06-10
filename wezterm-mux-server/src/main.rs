use clap::*;
use portable_pty::cmdbuilder::CommandBuilder;
use std::ffi::OsString;
use std::process::Command;
use wezterm_gui_subcommands::*;

mod daemonize;

#[derive(Debug, Parser)]
#[command(
    about = "Wez's Terminal Emulator\nhttp://github.com/wezterm/wezterm",
    version = config::wezterm_version(),
    trailing_var_arg = true,
)]
struct Opt {
    /// Skip loading wezterm.lua
    #[arg(long, short = 'n')]
    skip_config: bool,

    /// Specify the configuration file to use, overrides the normal
    /// configuration file resolution
    #[arg(
        long,
        value_parser,
        conflicts_with = "skip_config",
        value_hint=ValueHint::FilePath,
    )]
    config_file: Option<OsString>,

    /// Override specific configuration values
    #[arg(
        long = "config",
        name = "name=value",
        value_parser=clap::builder::ValueParser::new(name_equals_value),
        number_of_values = 1)]
    config_override: Vec<(String, String)>,

    /// Detach from the foreground and become a background process
    #[arg(long = "daemonize")]
    daemonize: bool,

    /// Specify the current working directory for the initially
    /// spawned program
    #[arg(long = "cwd", value_parser, value_hint=ValueHint::DirPath)]
    cwd: Option<OsString>,

    #[cfg(unix)]
    #[arg(long, hide = true)]
    pid_file_fd: Option<i32>,

    /// Instead of executing your shell, run PROG.
    /// For example: `wezterm start -- bash -l` will spawn bash
    /// as if it were a login shell.
    #[arg(value_parser, value_hint=ValueHint::CommandWithArguments, num_args=1..)]
    prog: Vec<OsString>,
}

fn main() {
    if let Err(err) = run() {
        wezterm_blob_leases::clear_storage();
        log::error!("{:#}", err);
        std::process::exit(1);
    }
    wezterm_blob_leases::clear_storage();
}

fn run() -> anyhow::Result<()> {
    let _saver = umask::UmaskSaver::new();
    let opts = Opt::parse();

    #[cfg(unix)]
    {
        if let Some(fd) = opts.pid_file_fd {
            daemonize::set_cloexec(fd, true);
        }
    }

    wezterm_mux_server::bootstrap_config(
        opts.config_file.as_ref(),
        &opts.config_override,
        opts.skip_config,
    )?;

    let config = config::configuration();

    #[cfg(unix)]
    let mut pid_file = None;

    #[cfg(unix)]
    {
        if opts.daemonize {
            pid_file = daemonize::daemonize(&config)?;
        }
    }

    if opts.daemonize {
        let mut cmd = Command::new(std::env::current_exe().unwrap());

        #[cfg(unix)]
        {
            if let Some(fd) = pid_file {
                cmd.arg("--pid-file-fd");
                cmd.arg(&fd.to_string());
            }
        }
        if opts.skip_config {
            cmd.arg("-n");
        }
        if let Some(f) = &opts.config_file {
            cmd.arg("--config-file");
            cmd.arg(f);
        }
        for (name, value) in &opts.config_override {
            cmd.arg("--config");
            cmd.arg(&format!("{name}={value}"));
        }
        if let Some(cwd) = opts.cwd {
            cmd.arg("--cwd");
            cmd.arg(cwd);
        }
        if !opts.prog.is_empty() {
            cmd.arg("--");
            for a in &opts.prog {
                cmd.arg(a);
            }
        }

        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.stdout(config.daemon_options.open_stdout()?);
            cmd.stderr(config.daemon_options.open_stderr()?);

            cmd.creation_flags(winapi::um::winbase::DETACHED_PROCESS);
            let child = cmd.spawn();
            drop(child);
            return Ok(());
        }

        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            if let Some(mask) = umask::UmaskSaver::saved_umask() {
                unsafe {
                    cmd.pre_exec(move || {
                        libc::umask(mask);
                        Ok(())
                    });
                }
            }

            return Err(anyhow::anyhow!("failed to re-exec: {:?}", cmd.exec()));
        }
    }

    wezterm_mux_server::scrub_env();
    wezterm_mux_server::init_blob_leases()?;

    let cmd = build_command(opts.prog, opts.cwd);

    wezterm_mux_server::init_mux()?;
    wezterm_mux_server::spawn_listeners(true)?;
    wezterm_mux_server::run_executor_loop(cmd)
}

fn build_command(prog: Vec<OsString>, cwd: Option<OsString>) -> Option<CommandBuilder> {
    let need_builder = !prog.is_empty() || cwd.is_some();
    if !need_builder {
        return None;
    }
    let mut builder = if prog.is_empty() {
        CommandBuilder::new_default_prog()
    } else {
        CommandBuilder::from_argv(prog)
    };
    if let Some(cwd) = cwd {
        builder.cwd(cwd);
    }
    Some(builder)
}
