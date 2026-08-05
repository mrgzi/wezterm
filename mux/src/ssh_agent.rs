use crate::{ClientId, Mux};
use anyhow::Context;
use chrono::{DateTime, Duration, Utc};
use parking_lot::RwLock;
#[cfg(unix)]
use std::os::unix::fs::symlink as symlink_file;
#[cfg(windows)]
use std::os::windows::fs::symlink_file;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;

/// AgentProxy manages an agent.PID symlink in the wezterm runtime
/// directory.
/// The intent is to maintain the symlink and have it point to the
/// appropriate ssh agent socket path for the most recently active
/// mux client.
///
/// Why symlink rather than running an agent proxy socket of our own?
/// Some agent implementations use low level unix socket operations
/// to decide whether the client process is allowed to consume
/// the agent or not, and us sitting in the middle breaks that.
///
/// As a further complication, when a wezterm proxy client is
/// present, both the proxy and the mux instance inside a gui
/// tend to be updated together, with the gui often being
/// touched last.
///
/// To deal with that we de-bounce input events and weight
/// proxy clients higher so that we can avoid thrashing
/// between gui and proxy.
///
/// The consequence of this is that there is 100ms of artificial
/// latency to detect a change in the active client.
/// This number was selected because it is unlike for a human
/// to be able to switch devices that quickly.
///
/// How is this used? The Mux::client_had_input function
/// will call AgentProxy::update_target to signal when
/// the active client may have changed.

pub struct AgentProxy {
    sock_path: PathBuf,
    current_target: RwLock<Option<Arc<ClientId>>>,
    sender: SyncSender<()>,
}

impl Drop for AgentProxy {
    fn drop(&mut self) {
        std::fs::remove_file(&self.sock_path).ok();
    }
}

fn update_symlink<P: AsRef<Path>, Q: AsRef<Path>>(original: P, link: Q) -> anyhow::Result<()> {
    let original = original.as_ref();
    let link = link.as_ref();

    match symlink_file(original, link) {
        Ok(()) => Ok(()),
        Err(err) => {
            if err.kind() == std::io::ErrorKind::AlreadyExists {
                std::fs::remove_file(link)
                    .with_context(|| format!("failed to remove {}", link.display()))?;
                symlink_file(original, link).with_context(|| {
                    format!(
                        "failed to create symlink {} -> {}: {err:#}",
                        link.display(),
                        original.display()
                    )
                })
            } else {
                anyhow::bail!(
                    "failed to create symlink {} -> {}: {err:#}",
                    link.display(),
                    original.display()
                );
            }
        }
    }
}

/// Is the process that owns an `agent.PID` symlink still running?
///
/// `kill(pid, 0)` succeeds for a live process we may signal and fails with
/// `EPERM` for a live process owned by somebody else; only `ESRCH` (and any
/// other error) means "gone". Answering "alive" when unsure is the safe
/// direction: it keeps a symlink that may still be in use, and the worst case
/// is that one file survives until the next start.
#[cfg(unix)]
fn agent_owner_is_alive(pid: i32) -> bool {
    if unsafe { libc::kill(pid, 0) } == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

/// Windows has no equally cheap liveness probe, so never prune there.
#[cfg(windows)]
fn agent_owner_is_alive(_pid: i32) -> bool {
    true
}

/// Remove `agent.PID` symlinks whose owning process is gone.
///
/// Termob fork: `AgentProxy::drop` removes our own symlink, but a mux that
/// exits on a signal (`SIGTERM` from a service manager or a container stop) or
/// through `std::process::exit` never runs `Drop`, so the runtime directory
/// gained one dangling symlink per run and never lost one (measured: 6995
/// `agent.*` entries, 200 out of 200 sampled pointing at dead pids).
///
/// Keyed on process liveness rather than age, because that is the actual
/// invariant: a dead pid's symlink can never become useful again, while a
/// young one may belong to a mux that started seconds ago.
fn prune_dead_agent_symlinks() {
    let Ok(dir) = std::fs::read_dir(&*config::RUNTIME_DIR) else {
        return;
    };
    for entry in dir.flatten() {
        let name = entry.file_name();
        // `pid > 0` is required, not cosmetic: `kill` reads 0 as "my whole
        // process group" and -1 as "every process I may signal", so a
        // hand-made `agent.0` or `agent.-1` would turn the probe into a
        // question about something else entirely. We only ever create
        // `agent.<getpid()>`, so anything outside that shape is not ours to
        // reason about.
        let Some(pid) = name
            .to_str()
            .and_then(|name| name.strip_prefix("agent."))
            .and_then(|pid| pid.parse::<i32>().ok())
            .filter(|pid| *pid > 0)
        else {
            continue;
        };
        if !agent_owner_is_alive(pid) {
            std::fs::remove_file(entry.path()).ok();
        }
    }
}

impl AgentProxy {
    pub fn new() -> Self {
        let pid = unsafe { libc::getpid() };
        // Before adding ours, clear out the ones their owners could not.
        prune_dead_agent_symlinks();
        let sock_path = config::RUNTIME_DIR.join(format!("agent.{pid}"));

        if let Some(inherited) = Self::default_ssh_auth_sock() {
            if let Err(err) = update_symlink(&inherited, &sock_path) {
                log::error!("failed to set {sock_path:?} to initial inherited SSH_AUTH_SOCK value of {inherited:?}: {err:#}");
            }
        }

        let (sender, receiver) = sync_channel(16);

        std::thread::spawn(move || Self::process_updates(receiver));

        Self {
            sock_path,
            current_target: RwLock::new(None),
            sender,
        }
    }

    pub fn default_ssh_auth_sock() -> Option<String> {
        match &config::configuration().default_ssh_auth_sock {
            Some(value) => Some(value.to_string()),
            None => std::env::var("SSH_AUTH_SOCK").ok(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.sock_path
    }

    pub fn update_target(&self) {
        // If the send fails, the channel is most likely
        // full, which means that the updater thread is
        // going to observe the now-current state when
        // it wakes up, so we needn't try any harder
        self.sender.try_send(()).ok();
    }

    fn process_updates(receiver: Receiver<()>) {
        while let Ok(_) = receiver.recv() {
            // De-bounce multiple input events so that we don't quickly
            // thrash between the host and proxy value
            std::thread::sleep(std::time::Duration::from_millis(100));
            while receiver.try_recv().is_ok() {}

            if let Some(mux) = Mux::try_get() {
                if let Some(agent) = &mux.agent {
                    agent.update_now();
                }
            }
        }
    }

    fn update_now(&self) {
        // Get list of clients from mux
        // Order by most recent activity
        // Take first one with auth sock -> that's the path
        // If we find none, then we print an error and drop
        // this stream.

        let mut clients = Mux::get().iter_clients();
        clients.retain(|info| info.client_id.ssh_auth_sock.is_some());

        clients.sort_by(|a, b| {
            // The biggest last_input time is most recent, so it sorts sooner.
            // However, when using a proxy into a gui mux, both the proxy and the
            // gui will update around the same time, with the gui often being
            // updated fractionally after the proxy.
            // In this situation we want the proxy to be selected, so we weight
            // proxy entries slightly higher by adding a small Duration to
            // the actual observed value.
            // `via proxy pid` is coupled with the Pdu::SetClientId logic
            // in wezterm-mux-server-impl/src/sessionhandler.rs
            const PROXY_MARKER: &str = "via proxy pid";
            let a_proxy = a.client_id.hostname.contains(PROXY_MARKER);
            let b_proxy = b.client_id.hostname.contains(PROXY_MARKER);

            fn adjust_for_proxy(time: DateTime<Utc>, is_proxy: bool) -> DateTime<Utc> {
                if is_proxy {
                    time + Duration::milliseconds(100)
                } else {
                    time
                }
            }

            let a_time = adjust_for_proxy(a.last_input, a_proxy);
            let b_time = adjust_for_proxy(b.last_input, b_proxy);

            b_time.cmp(&a_time)
        });

        log::trace!("filtered to {clients:#?}");
        match clients.get(0) {
            Some(info) => {
                let current = self.current_target.read().clone();
                let needs_update = match (current, &info.client_id) {
                    (None, _) => true,
                    (Some(prior), current) => prior != *current,
                };

                if needs_update {
                    let ssh_auth_sock = info
                        .client_id
                        .ssh_auth_sock
                        .as_ref()
                        .expect("we checked in the retain above");
                    log::trace!(
                        "Will update {} -> {ssh_auth_sock}",
                        self.sock_path.display(),
                    );
                    self.current_target.write().replace(info.client_id.clone());

                    if let Err(err) = update_symlink(ssh_auth_sock, &self.sock_path) {
                        log::error!(
                            "Problem updating {} -> {ssh_auth_sock}: {err:#}",
                            self.sock_path.display(),
                        );
                    }
                }
            }
            None => {
                if self.current_target.write().take().is_some() {
                    log::trace!("Updating agent to be bogus");
                    if let Err(err) = update_symlink(".", &self.sock_path) {
                        log::error!(
                            "Problem updating {} -> .: {err:#}",
                            self.sock_path.display()
                        );
                    }
                }
            }
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::agent_owner_is_alive;

    /// The liveness probe must not be inverted: reporting a live process as
    /// dead would make `prune_dead_agent_symlinks` delete the symlink that a
    /// running mux is actively serving. Our own pid is the one case that can be
    /// asserted with certainty.
    #[test]
    fn own_process_is_alive() {
        let me = std::process::id() as i32;
        assert!(agent_owner_is_alive(me), "our own pid must read as alive");
    }

    /// A live process we may not signal must still read as alive: `kill` fails
    /// with `EPERM` there, and treating that as "gone" would prune another
    /// user's symlink. pid 1 always exists and is root-owned, so this covers
    /// the `EPERM` branch unless the tests run as root -- in which case the
    /// `Ok` branch is taken and the assertion still holds.
    #[test]
    fn process_owned_by_another_user_is_alive() {
        assert!(
            agent_owner_is_alive(1),
            "pid 1 exists; EPERM must not be read as gone"
        );
    }

    /// A reaped child is definitively gone (waited on, so no zombie keeps the
    /// pid occupied) and its symlink is safe to prune.
    #[test]
    fn reaped_child_is_not_alive() {
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn true");
        let pid = child.id() as i32;
        child.wait().expect("reap child");
        assert!(
            !agent_owner_is_alive(pid),
            "a reaped child's pid must read as gone"
        );
    }
}
