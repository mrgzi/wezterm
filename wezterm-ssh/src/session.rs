use crate::auth::*;
use crate::config::ConfigMap;
use crate::host::*;
use crate::pty::*;
use crate::sessioninner::*;
use crate::sftp::{Sftp, SftpRequest};
use filedescriptor::{socketpair, FileDescriptor};
use portable_pty::PtySize;
use smol::channel::{bounded, Receiver, Sender};
use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum SessionEvent {
    Banner(Option<String>),
    HostVerify(HostVerificationEvent),
    Authenticate(AuthenticationEvent),
    HostVerificationFailed(HostVerificationFailed),
    Error(String),
    Authenticated,
}

#[derive(Debug, Clone)]
pub(crate) struct SessionSender {
    pub tx: Sender<SessionRequest>,
    pub pipe: Arc<Mutex<FileDescriptor>>,
}

impl SessionSender {
    fn post_send(&self) {
        let mut pipe = self.pipe.lock().unwrap();
        let _ = pipe.write(b"x");
    }

    pub fn try_send(&self, event: SessionRequest) -> anyhow::Result<()> {
        self.tx.try_send(event)?;
        self.post_send();
        Ok(())
    }

    /// Termob fork: queue an event that must not be lost to a full queue,
    /// displacing the oldest one where it is.
    ///
    /// For the two events that say the connection is finished. `try_send`
    /// reports a full queue as an error, and both callers are places where an
    /// error can only be discarded — so a queue that happened to be full at
    /// that moment left the session running with nobody left to stop it. What
    /// is displaced is a request addressed to a connection that is ending, so
    /// there is nothing to lose by dropping it.
    pub fn force_send(&self, event: SessionRequest) {
        self.tx.force_send(event).ok();
        self.post_send();
    }

    pub async fn send(&self, event: SessionRequest) -> anyhow::Result<()> {
        self.tx.send(event).await?;
        self.post_send();
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
#[error("SSH session is dead")]
pub struct DeadSession;

#[derive(Debug)]
pub(crate) enum SessionRequest {
    NewPty(NewPty, Sender<anyhow::Result<(SshPty, SshChildProcess)>>),
    ResizePty(ResizePty, Option<Sender<anyhow::Result<()>>>),
    Exec(Exec, Sender<anyhow::Result<ExecResult>>),
    Sftp(SftpRequest),
    SignalChannel(SignalChannel),
    SessionDropped,
    /// Close the connection now, whatever is still open on it.
    ///
    /// `SessionDropped` is the passive form of this: it says the handles are
    /// gone and lets the session finish once its channels have drained. That is
    /// the right answer when the caller has merely stopped holding it, and the
    /// wrong one when the caller has decided the connection is finished —
    /// draining then depends on how the last channel's output happened to fall,
    /// so the connection outlives the decision by an amount nobody can predict.
    Shutdown,
}

#[derive(Debug)]
pub(crate) struct SignalChannel {
    pub channel: ChannelId,
    pub signame: &'static str,
}

#[derive(Debug)]
pub(crate) struct Exec {
    pub command_line: String,
    pub env: Option<HashMap<String, String>>,
}

#[derive(Clone)]
pub struct Session {
    tx: SessionSender,
    /// Termob fork: announces the drop when the LAST handle goes, and not
    /// before.
    ///
    /// This type is a handle and is cloned as a matter of course — the domain
    /// keeps one, the thread carrying out authentication is given one, and
    /// `connected_session()` hands one to anybody who asks. A `Drop` on the
    /// handle itself therefore told the session it was finished every time one
    /// of those went out of scope, and the session then stopped the moment it
    /// had no channel. A clone taken and returned unused, between a connection
    /// being authenticated and its first pty being granted, ended it outright.
    /// Named with a leading underscore: it is held for its `Drop` and read by
    /// nothing.
    _alive: Arc<SessionAlive>,
    /// Termob fork: how long the far end has been holding something of ours it
    /// has not acknowledged, in milliseconds. Written by the session thread,
    /// read from anywhere. See [`Session::unanswered_for`].
    unanswered_ms: Arc<AtomicU64>,
    /// Termob fork: whether the session thread has got as far as serving
    /// requests. See [`Session::is_established`].
    established: Arc<AtomicBool>,
    /// Termob fork: whether authentication was won by a public key.
    /// See [`Session::authenticated_with_key`].
    authenticated_with_key: Arc<AtomicBool>,
}

/// Termob fork: the one owner of the "these handles are gone" signal.
///
/// Held by every [`Session`] through an `Arc`, so the message is sent once, when
/// the last of them drops.
struct SessionAlive {
    tx: SessionSender,
}

impl Drop for SessionAlive {
    fn drop(&mut self) {
        self.tx.force_send(SessionRequest::SessionDropped);
        log::trace!("Drop Session");
    }
}

impl Session {
    pub fn connect(config: ConfigMap) -> anyhow::Result<(Self, Receiver<SessionEvent>)> {
        let (tx_event, rx_event) = bounded(8);
        let (tx_req, rx_req) = bounded(8);
        let (mut sender_write, mut sender_read) = socketpair()?;
        sender_write.set_non_blocking(true)?;
        sender_read.set_non_blocking(true)?;

        let session_sender = SessionSender {
            tx: tx_req,
            pipe: Arc::new(Mutex::new(sender_write)),
        };

        let keep_alive = config.get("serveraliveinterval").and_then(|value| {
            let seconds: u64 = value.parse().ok()?;
            if seconds == 0 {
                None
            } else {
                Some(Duration::from_secs(seconds))
            }
        });

        let now = Instant::now();
        let unanswered_ms = Arc::new(AtomicU64::new(0));
        let established = Arc::new(AtomicBool::new(false));
        let authenticated_with_key = Arc::new(AtomicBool::new(false));

        let mut inner = SessionInner {
            config,
            tx_event,
            rx_req,
            channels: HashMap::new(),
            files: HashMap::new(),
            dirs: HashMap::new(),
            next_channel_id: 1,
            next_file_id: 1,
            sender_read,
            session_was_dropped: false,
            shutdown_requested: false,
            shown_accept_env_error: false,
            last_keep_alive: now,
            keep_alive,
            established: Arc::clone(&established),
            authenticated_with_key: Arc::clone(&authenticated_with_key),
            undelivered_since: None,
            unanswered_ms: Arc::clone(&unanswered_ms),
        };
        std::thread::spawn(move || inner.run());
        Ok((
            Self {
                tx: session_sender.clone(),
                _alive: Arc::new(SessionAlive { tx: session_sender }),
                unanswered_ms,
                established,
                authenticated_with_key,
            },
            rx_event,
        ))
    }

    /// Termob fork: close this connection now.
    ///
    /// Takes the handle by value because there is nothing left to do with it,
    /// and because a caller that has decided the connection is finished should
    /// not still be holding one. Dropping every handle would eventually have
    /// the same effect, but only once the channels have drained — which is not
    /// a moment anything can predict, so it is not one a user can be given.
    ///
    /// The request displaces the oldest queued one if it has to (`force_send`):
    /// a full queue is a moment, and losing the close to one would leave the
    /// connection running with nothing left holding a handle to stop it.
    pub fn shutdown(self) {
        self.tx.force_send(SessionRequest::Shutdown);
    }

    /// Termob fork: whether there is still a session thread behind this handle.
    ///
    /// That thread owns the receiving end of the request queue, so the queue
    /// being closed IS the thread having ended — however it ended: the owner
    /// closed the connection, the far end went away, or the transport was lost.
    ///
    /// Nothing else records the difference. A handle stays valid-looking for
    /// ever, so a holder that had one reported the connection as live long
    /// after there was anything on the other end of it, and every request it
    /// made was queued for a thread that was never going to read it.
    #[must_use]
    pub fn is_alive(&self) -> bool {
        !self.tx.tx.is_closed()
    }

    /// Termob fork: has this session finished being established?
    ///
    /// `false` from the moment [`Session::connect`] returns until the thread
    /// behind it has resolved the address, opened the transport and
    /// authenticated. The handle exists throughout — that is the whole point of
    /// it, since authentication is carried out in the pane the caller has
    /// already been given — so nothing else distinguishes a connection that is
    /// being made from one that is working. A holder that reads only
    /// [`Session::is_alive`] therefore reports a connection which may still
    /// fail, and does so for as long as the attempt takes: on a host that is
    /// not there, the whole connect timeout.
    ///
    /// It does not go back to `false`. A session that has been established and
    /// then lost is a session whose thread has ended, which `is_alive` answers.
    #[must_use]
    pub fn is_established(&self) -> bool {
        self.established.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Termob fork: how long the far end has been holding something this
    /// connection sent it without acknowledging it.
    ///
    /// Zero while it is keeping up, which is the ordinary state — a connection
    /// answering within its round trip never leaves anything outstanding for a
    /// whole turn of the session loop. A growing figure is the one signal that
    /// distinguishes a connection that has stopped answering from a quiet one,
    /// and it grows before anything else notices: the transport is not declared
    /// dead until the operating system abandons it, deliberately, so that a
    /// connection worth keeping survives a few lost seconds.
    ///
    /// Also zero where the platform is not asked (Windows), so a reader that
    /// wants to say "no answer" must not read zero as proof of health there.
    #[must_use]
    pub fn unanswered_for(&self) -> Duration {
        Duration::from_millis(self.unanswered_ms.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Termob fork: did a public key win this session's authentication?
    ///
    /// `true` once a key — from the agent or from an identity file — was
    /// accepted; `false` for a password, for keyboard-interactive, and for a
    /// server that asked for nothing.
    ///
    /// **A fact this side already has, which the far end would otherwise have to
    /// be asked for.** A client that offers to install a key at a host wants to
    /// know whether that host already takes one, and the honest answer is one
    /// round trip down the queue this session serves its channels on. It is also
    /// unnecessary: authentication has just happened, and what won it is known
    /// here. The loop returns from whichever branch succeeded and said nothing
    /// about which, so nothing outside could tell a key login from a password
    /// one.
    ///
    /// It does not go back to `false`. It describes how this session was
    /// authenticated, which is settled once and for the life of the session.
    ///
    /// PR candidate: additive, one atomic, no behaviour changed.
    #[must_use]
    pub fn authenticated_with_key(&self) -> bool {
        self.authenticated_with_key
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub async fn request_pty(
        &self,
        term: &str,
        size: PtySize,
        command_line: Option<&str>,
        env: Option<HashMap<String, String>>,
    ) -> anyhow::Result<(SshPty, SshChildProcess)> {
        let (reply, rx) = bounded(1);
        // A pty request crosses two thread boundaries — queued here, served by
        // the session thread — and the wait either side of that boundary has
        // entirely different causes. Timed separately because the whole of it
        // otherwise reads as "the pty took a while", which is the one reading
        // that explains nothing.
        let queued = std::time::Instant::now();
        self.tx
            .send(SessionRequest::NewPty(
                NewPty {
                    term: term.to_string(),
                    size,
                    command_line: command_line.map(|s| s.to_string()),
                    env,
                },
                reply,
            ))
            .await
            .map_err(|_| DeadSession)?;
        let sent = queued.elapsed();
        // A reply that never comes means the same thing as a request that
        // could not be sent: the session thread is no longer there. The two
        // differ only in whether it stopped before or after the request was
        // queued, and a caller that recovers from `DeadSession` — by opening a
        // new session — has to recover from both or it fails outright on the
        // narrower of the two.
        let (mut ssh_pty, mut child) = rx.recv().await.map_err(|_| DeadSession)??;
        log::debug!(
            "NewPty queued in {sent:?}, served in {:?}",
            queued.elapsed() - sent
        );
        ssh_pty.tx.replace(self.tx.clone());
        child.tx.replace(self.tx.clone());
        Ok((ssh_pty, child))
    }

    pub async fn exec(
        &self,
        command_line: &str,
        env: Option<HashMap<String, String>>,
    ) -> anyhow::Result<ExecResult> {
        let (reply, rx) = bounded(1);
        self.tx
            .send(SessionRequest::Exec(
                Exec {
                    command_line: command_line.to_string(),
                    env,
                },
                reply,
            ))
            .await
            .map_err(|_| DeadSession)?;
        // See `request_pty`: a reply that never comes is a dead session too.
        let mut exec = rx.recv().await.map_err(|_| DeadSession)??;
        exec.child.tx.replace(self.tx.clone());
        Ok(exec)
    }

    /// Creates a new reference to the sftp channel for filesystem operations
    ///
    /// ### Note
    ///
    /// This does not actually initialize the sftp subsystem and only provides
    /// a reference to a means to perform sftp operations. Upon requesting the
    /// first sftp operation, the sftp subsystem will be initialized.
    pub fn sftp(&self) -> Sftp {
        Sftp {
            tx: self.tx.clone(),
        }
    }
}

#[derive(Debug)]
pub struct ExecResult {
    pub stdin: FileDescriptor,
    pub stdout: FileDescriptor,
    pub stderr: FileDescriptor,
    pub child: SshChildProcess,
}
