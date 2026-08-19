use crate::channelwrap::ChannelWrap;
use crate::config::ConfigMap;
use crate::dirwrap::DirWrap;
use crate::filewrap::FileWrap;
use crate::pty::*;
use crate::session::{Exec, ExecResult, SessionEvent, SessionRequest, SignalChannel};
use crate::sessionwrap::SessionWrap;
use crate::sftp::dir::{Dir, DirId, DirRequest};
use crate::sftp::file::{File, FileId, FileRequest};
use crate::sftp::{OpenWithMode, SftpChannelResult, SftpRequest};
use crate::sftpwrap::SftpWrap;
use anyhow::{anyhow, Context};
use camino::Utf8PathBuf;
use filedescriptor::{
    poll, pollfd, socketpair, AsRawSocketDescriptor, FileDescriptor, SocketDescriptor, POLLIN,
    POLLOUT,
};
use portable_pty::ExitStatus;
use smol::channel::{bounded, Receiver, Sender, TryRecvError};
use socket2::{Domain, Socket, Type};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::net::ToSocketAddrs;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Termob fork: shortest wait in the session poll loop, and the value the
/// backoff resets to after any activity.
const MIN_POLL_DELAY: Duration = Duration::from_millis(100);

/// Termob fork: upper bound for the poll backoff.
///
/// The wait is a *fallback*: bytes already buffered inside the ssh library no
/// longer make the socket readable, so nothing wakes the loop for them and
/// they are only picked up when the poll times out. An unbounded backoff
/// therefore turns into unbounded latency for that case; the cap keeps the
/// worst case at a quarter second while an idle session still avoids
/// busy-polling.
const MAX_POLL_DELAY: Duration = Duration::from_millis(250);

/// Termob fork: how long what we have sent may go unacknowledged before the
/// operating system declares the connection dead, in seconds.
///
/// The keepalive above it sends an IGNORE packet every `ServerAliveInterval`
/// and nothing ever answers one, so a peer that has stopped listening is
/// discovered by the ACK that does not come rather than by a reply that does —
/// which is the only detector available here, because libssh's own
/// `ssh_send_keepalive` (a global request that DOES demand an answer) is not
/// exposed by the Rust binding. Left to the defaults, that discovery takes the
/// full retransmission budget: minutes on macOS, and until then the session is
/// a black hole that accepts requests and answers none.
///
/// Twenty seconds is above any transient a live connection survives — a
/// handover or a lost radio second is a handful of retransmissions — and well
/// below the interval, so a vanished peer is known within one keepalive period
/// plus this. It is not a way to survive a change of network: a TCP connection
/// belongs to the address it was opened from, so moving to another one ends it
/// whatever this says.
const TRANSPORT_UNACKED_LIMIT: Duration = Duration::from_secs(20);

/// Termob fork: the socket options every SSH transport is opened with.
///
/// `ssh(1)` sets `TCP_NODELAY` on its own socket and libssh sets it on sockets
/// IT opens (`SSH_OPTIONS_NODELAY`, defaulting to off, applied in its own
/// connect path). This socket is opened here and handed over as a descriptor,
/// so neither of them ever reaches it: without this, every packet small enough
/// to be worth coalescing waits on Nagle's algorithm for an acknowledgement
/// that the peer is holding back on its own delayed-ACK timer.
///
/// Failures are absorbed. Both options are advice about how a healthy
/// connection should behave; a kernel that refuses one is not a reason to
/// refuse the connection, and the caller has no better answer than to carry on
/// without it.
fn set_transport_options(sock: &Socket) {
    if let Err(err) = sock.set_nodelay(true) {
        log::warn!("could not disable Nagle on the ssh transport: {err:#}");
    }
    if let Err(err) = set_unacked_data_limit(sock, TRANSPORT_UNACKED_LIMIT) {
        log::warn!("could not bound the ssh transport's retransmission: {err:#}");
    }
}

/// Termob fork: drop the connection once data has gone unacknowledged for
/// `limit`. See [`TRANSPORT_UNACKED_LIMIT`].
///
/// The two platforms name this differently and count it differently — seconds
/// here, milliseconds there — and neither unit is documented where the option
/// is; finding: F-006. TCP keepalive does not answer this case: it runs only
/// while the connection is idle, and a vanished peer leaves data in flight.
///
/// Windows is deliberately absent rather than unimplemented: its own
/// `TcpMaxDataRetransmissions` default already bounds this at the same order of
/// magnitude, whereas the BSD and Linux defaults are minutes.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn set_unacked_data_limit(sock: &Socket, limit: Duration) -> std::io::Result<()> {
    use std::convert::TryFrom;
    // Milliseconds on this platform, seconds on the other.
    let millis = u32::try_from(limit.as_millis()).unwrap_or(u32::MAX);
    set_tcp_option(sock, libc::TCP_USER_TIMEOUT, millis)
}

/// Termob fork: see the Linux arm above.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn set_unacked_data_limit(sock: &Socket, limit: Duration) -> std::io::Result<()> {
    /// `TCP_RXT_CONNDROPTIME` from `<netinet/tcp.h>`: "time after which tcp
    /// retransmissions will be stopped and the connection will be dropped".
    /// Named here because the `libc` crate does not carry it.
    const TCP_RXT_CONNDROPTIME: libc::c_int = 0x80;
    use std::convert::TryFrom;
    let secs = u32::try_from(limit.as_secs()).unwrap_or(u32::MAX);
    set_tcp_option(sock, TCP_RXT_CONNDROPTIME, secs)
}

/// Termob fork: see the Linux arm above. Nothing to do on this platform.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn set_unacked_data_limit(_sock: &Socket, _limit: Duration) -> std::io::Result<()> {
    Ok(())
}

/// Termob fork: how many bytes the far end has not taken delivery of.
///
/// Unsent and unacknowledged together — everything the kernel is still holding
/// on this connection's behalf. Zero means the peer has acknowledged all of it,
/// which is the only fact that distinguishes a quiet connection from one that
/// has stopped answering: nothing arriving is equally consistent with a command
/// that has printed nothing yet.
///
/// `None` where the platform is not asked, or the call fails. A caller must
/// read that as "no answer available", never as zero.
///
/// One integer on each platform, deliberately: the richer interfaces
/// (`TCP_CONNECTION_INFO`, `TCP_INFO`) mean mirroring a kernel struct whose
/// layout is not ours, for figures beyond this one that nothing here needs.
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn undelivered_bytes(sock: SocketDescriptor) -> Option<u32> {
    let mut value: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&value) as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            sock,
            libc::SOL_SOCKET,
            libc::SO_NWRITE,
            std::ptr::addr_of_mut!(value).cast(),
            &mut len,
        )
    };
    (rc == 0).then(|| value.max(0) as u32)
}

/// Termob fork: see the Apple arm above.
#[cfg(any(target_os = "linux", target_os = "android"))]
fn undelivered_bytes(sock: SocketDescriptor) -> Option<u32> {
    let mut value: libc::c_int = 0;
    let rc = unsafe { libc::ioctl(sock, libc::TIOCOUTQ, std::ptr::addr_of_mut!(value)) };
    (rc == 0).then(|| value.max(0) as u32)
}

/// Termob fork: see the Apple arm above. This platform is not asked.
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
)))]
fn undelivered_bytes(_sock: SocketDescriptor) -> Option<u32> {
    None
}

/// Termob fork: set one integer `IPPROTO_TCP` option on `sock`.
///
/// `socket2` covers neither of the options above, so the call is made directly.
/// The unsafety is the FFI call itself: the value outlives it, its length is
/// its own, and the descriptor is borrowed for the duration.
#[cfg(any(
    target_os = "linux",
    target_os = "android",
    target_os = "macos",
    target_os = "ios"
))]
fn set_tcp_option(sock: &Socket, option: libc::c_int, value: u32) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let value = value as libc::c_uint;
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::IPPROTO_TCP,
            option,
            std::ptr::addr_of!(value).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[derive(Debug)]
pub(crate) struct DescriptorState {
    pub fd: Option<FileDescriptor>,
    pub buf: VecDeque<u8>,
}

pub(crate) struct ChannelInfo {
    pub channel_id: ChannelId,
    pub channel: ChannelWrap,
    pub exit: Option<Sender<ExitStatus>>,
    pub exited: bool,
    pub descriptors: [DescriptorState; 3],
}

pub(crate) type ChannelId = usize;

pub(crate) struct SessionInner {
    pub config: ConfigMap,
    pub tx_event: Sender<SessionEvent>,
    pub rx_req: Receiver<SessionRequest>,
    pub channels: HashMap<ChannelId, ChannelInfo>,
    pub files: HashMap<FileId, FileWrap>,
    pub dirs: HashMap<DirId, DirWrap>,
    pub next_channel_id: ChannelId,
    pub next_file_id: FileId,
    pub sender_read: FileDescriptor,
    pub session_was_dropped: bool,
    /// Termob fork: the embedder has closed this connection. Unlike
    /// `session_was_dropped` this does not wait for the channels to drain — see
    /// `SessionRequest::Shutdown`.
    pub shutdown_requested: bool,
    pub shown_accept_env_error: bool,
    pub last_keep_alive: Instant,
    pub keep_alive: Option<Duration>,
    /// Termob fork: when the far end was last holding something of ours it had
    /// not acknowledged, and had not acknowledged it since. `None` while the
    /// connection is answering. See [`SessionInner::note_delivery`].
    /// Termob fork: set once this session reaches its request loop, which is
    /// the moment it is authenticated and serving. Before that the thread is
    /// still resolving, connecting and authenticating — a state a holder of the
    /// handle cannot otherwise tell from a working connection, because the
    /// handle and its thread exist throughout. See [`crate::Session::is_established`].
    pub established: Arc<AtomicBool>,
    pub undelivered_since: Option<Instant>,
    /// Termob fork: the same thing, in milliseconds, for a holder of the
    /// [`crate::Session`] handle to read from its own thread. Zero means the
    /// far end is keeping up — the only value it takes while all is well, so a
    /// reader needs no second flag.
    pub unanswered_ms: Arc<AtomicU64>,
}

impl Drop for SessionInner {
    fn drop(&mut self) {
        log::trace!("Dropping SessionInner");
    }
}

impl SessionInner {
    pub fn run(&mut self) {
        if let Err(err) = self.run_impl() {
            self.tx_event
                .try_send(SessionEvent::Error(format!("{:#}", err)))
                .ok();
        }
    }

    fn run_impl(&mut self) -> anyhow::Result<()> {
        let backend = self
            .config
            .get("wezterm_ssh_backend")
            .map(|s| s.as_str())
            .unwrap_or(
                #[cfg(feature = "libssh-rs")]
                "libssh",
                #[cfg(not(feature = "libssh-rs"))]
                "ssh2",
            );
        match backend {
            #[cfg(feature = "ssh2")]
            "ssh2" => self.run_impl_ssh2(),

            #[cfg(not(feature = "ssh2"))]
            "ssh2" => anyhow::bail!(
                "invalid wezterm_ssh_backend value: {}, not compiled with `ssh2`",
                backend
            ),

            #[cfg(feature = "libssh-rs")]
            "libssh" => self.run_impl_libssh(),

            #[cfg(not(feature = "libssh-rs"))]
            "libssh" => anyhow::bail!(
                "invalid wezterm_ssh_backend value: {}, not compiled with `libssh`",
                backend
            ),

            _ => anyhow::bail!(
                "invalid wezterm_ssh_backend value: {}, expected either `ssh2` or `libssh`",
                backend
            ),
        }
    }

    #[cfg(feature = "libssh-rs")]
    fn run_impl_libssh(&mut self) -> anyhow::Result<()> {
        let hostname = self
            .config
            .get("hostname")
            .ok_or_else(|| anyhow!("hostname not present in config"))?
            .to_string();
        let user = self
            .config
            .get("user")
            .ok_or_else(|| anyhow!("username not present in config"))?
            .to_string();
        let port = self
            .config
            .get("port")
            .ok_or_else(|| anyhow!("port is always set in config loader"))?
            .parse::<u16>()?;

        self.tx_event
            .try_send(SessionEvent::Banner(Some(format!(
                "Using libssh-rs to connect to {}@{}:{}",
                user, hostname, port
            ))))
            .context("notifying user of banner")?;

        let sess = libssh_rs::Session::new()?;
        let verbose = self
            .config
            .get("wezterm_ssh_verbose")
            .map(|s| s.as_str())
            .unwrap_or("false")
            == "true";
        if verbose {
            sess.set_option(libssh_rs::SshOption::LogLevel(libssh_rs::LogLevel::Packet))?;

            /// libssh logs to stderr, but on Windows in the GUI there isn't a valid
            /// stderr for it to log to.
            /// So, we redirect logging via our own log callback and pipe it via
            /// the `log` crate.
            unsafe extern "C" fn log_callback(
                _priority: std::os::raw::c_int,
                function: *const std::os::raw::c_char,
                message: *const std::os::raw::c_char,
                _userdata: *mut std::os::raw::c_void,
            ) {
                use std::ffi::CStr;
                let function = CStr::from_ptr(function).to_string_lossy().to_string();
                let message = CStr::from_ptr(message).to_string_lossy().to_string();

                // The message typically has "function: message" prefixed, which
                // looks redundant when logged with the function prefix by the
                // logging crate.
                // Strip that off!
                let message = match message.strip_prefix(&format!("{}: ", function)) {
                    Some(m) => m,
                    None => &message,
                };

                log::logger().log(
                    &log::Record::builder()
                        .args(format_args!("{}", message))
                        .level(log::Level::Info)
                        .module_path(Some(&function))
                        .target(&format!("libssh::{}", function))
                        .build(),
                );
            }
            unsafe {
                libssh_rs::sys::ssh_set_log_callback(Some(log_callback));
            }
        }
        sess.set_option(libssh_rs::SshOption::Hostname(hostname.clone()))?;
        sess.set_option(libssh_rs::SshOption::User(Some(user)))?;
        sess.set_option(libssh_rs::SshOption::Port(port))?;
        sess.options_parse_config(None)?; // FIXME: overridden config path?
        if let Some(agent) = self.config.get("identityagent") {
            sess.set_option(libssh_rs::SshOption::IdentityAgent(Some(agent.clone())))?;
        }
        // Termob fork: `split_path_list` rather than `split_whitespace` so a
        // path containing a space survives; see its doc comment.
        if let Some(files) = self.config.get("identityfile") {
            for file in crate::config::split_path_list(files) {
                sess.set_option(libssh_rs::SshOption::AddIdentity(file))?;
            }
        }
        if let Some(kh) = self.config.get("userknownhostsfile") {
            for file in crate::config::split_path_list(kh) {
                sess.set_option(libssh_rs::SshOption::KnownHosts(Some(file)))?;
                break;
            }
        }
        if let Some(types) = self.config.get("pubkeyacceptedtypes") {
            sess.set_option(libssh_rs::SshOption::PublicKeyAcceptedTypes(
                types.to_string(),
            ))?;
        }
        if let Some(bind_addr) = self.config.get("bindaddress") {
            sess.set_option(libssh_rs::SshOption::BindAddress(bind_addr.to_string()))?;
        }
        if let Some(host_key) = self.config.get("hostkeyalgorithms") {
            sess.set_option(libssh_rs::SshOption::HostKeys(host_key.to_string()))?;
        }

        // Termob fork: no blocking call waits for ever.
        //
        // Every request the embedder makes is served on this one thread with
        // the session in blocking mode, and libssh resolves a blocking wait to
        // `SSH_TIMEOUT_INFINITE` unless this option carries a value
        // (`ssh_handle_packets_termination`). Against a peer that has stopped
        // answering — a network changed under a live connection, which is the
        // ordinary case on a phone — opening one channel therefore blocked the
        // session thread until TCP gave up, and with it every other pane, the
        // request to close the connection, and the whole of the next tab the
        // user tried to open. The wait is what turns "this connection is gone"
        // into an error somebody can be told about.
        //
        // It is set AFTER `options_parse_config` on purpose: libssh maps
        // `ConnectTimeout` onto this same value, so a user's ssh config would
        // otherwise decide how long the product may hang for. Connecting has
        // its own bound (`connect_timeout`); this one is about everything
        // after.
        //
        // Generous, because it is the backstop rather than the detector: the
        // socket is dropped by the operating system long before this
        // (`TRANSPORT_UNACKED_LIMIT`), and the one legitimate wait of this
        // order is a server holding an authentication reply while a second
        // factor is answered somewhere else.
        const BLOCKING_CALL_LIMIT: Duration = Duration::from_secs(60);
        sess.set_option(libssh_rs::SshOption::Timeout(BLOCKING_CALL_LIMIT))?;

        // The transport handshake is timed on its own, so that a slow network
        // can be told apart from a slow authentication.
        //
        // `mux::ssh` reports the time to authenticate and the time to a pty;
        // both of those contain this one, and the two have entirely different
        // causes — a distant host, against a server asking for method after
        // method. Only the libssh path carries this, because it is the only
        // backend the product selects.
        let handshake_started = Instant::now();
        let (sock, _child) = self.connect_to_host(&hostname, port, verbose)?;
        let raw = {
            #[cfg(unix)]
            {
                use std::os::unix::io::IntoRawFd;
                sock.into_raw_fd()
            }
            #[cfg(windows)]
            {
                use std::os::windows::io::IntoRawSocket;
                sock.into_raw_socket()
            }
        };

        sess.set_option(libssh_rs::SshOption::Socket(raw))?;

        sess.connect()
            .with_context(|| format!("Connecting to {hostname}:{port}"))?;
        log::info!(
            "ssh transport handshake to {hostname}:{port} took {:?}",
            handshake_started.elapsed()
        );

        let banner = sess.get_server_banner()?;
        self.tx_event
            .try_send(SessionEvent::Banner(Some(banner)))
            .context("notifying user of banner")?;

        self.host_verification_libssh(&sess, &hostname, port)?;
        self.authenticate_libssh(&sess)?;

        if let Ok(banner) = sess.get_issue_banner() {
            self.tx_event
                .try_send(SessionEvent::Banner(Some(banner)))
                .context("notifying user of banner")?;
        }

        self.tx_event
            .try_send(SessionEvent::Authenticated)
            .context("notifying user that session is authenticated")?;

        if let Some("yes") = self.config.get("forwardagent").map(|s| s.as_str()) {
            if self.identity_agent().is_some() {
                sess.enable_accept_agent_forward(true);
            } else {
                log::error!("ForwardAgent is set to yes, but IdentityAgent is not set");
            }
        }
        sess.set_blocking(false);
        let mut sess = SessionWrap::with_libssh(sess);
        // The boundary between "the session is
        // ready" and "the session is serving requests". Everything the
        // embedder asks for lands after this point, so a delay before it and
        // a delay inside the loop have entirely different causes and are
        // otherwise indistinguishable from the outside.
        log::debug!("ssh session authenticated; entering request loop");
        self.request_loop(&mut sess)
    }

    #[cfg(feature = "ssh2")]
    fn run_impl_ssh2(&mut self) -> anyhow::Result<()> {
        let verbose = self
            .config
            .get("wezterm_ssh_verbose")
            .map(|s| s.as_str())
            .unwrap_or("false")
            == "true";

        let hostname = self
            .config
            .get("hostname")
            .ok_or_else(|| anyhow!("hostname not present in config"))?
            .to_string();
        let user = self
            .config
            .get("user")
            .ok_or_else(|| anyhow!("username not present in config"))?
            .to_string();
        let port = self
            .config
            .get("port")
            .ok_or_else(|| anyhow!("port is always set in config loader"))?
            .parse::<u16>()?;
        let remote_address = format!("{}:{}", hostname, port);

        self.tx_event
            .try_send(SessionEvent::Banner(Some(format!(
                "Using ssh2 to connect to {}@{}:{}",
                user, hostname, port
            ))))
            .context("notifying user of banner")?;

        let (sock, _child) = self.connect_to_host(&hostname, port, verbose)?;

        let mut sess = ssh2::Session::new()?;
        if verbose {
            sess.trace(ssh2::TraceFlags::all());
        }
        sess.set_blocking(true);
        sess.set_tcp_stream(sock);
        sess.handshake()
            .with_context(|| format!("ssh handshake with {}", remote_address))?;

        self.tx_event
            .try_send(SessionEvent::Banner(sess.banner().map(|s| s.to_string())))
            .context("notifying user of banner")?;

        self.host_verification(&sess, &hostname, port, &remote_address)
            .context("host verification")?;

        self.authenticate(&sess, &user, &hostname)
            .context("authentication")?;

        self.tx_event
            .try_send(SessionEvent::Authenticated)
            .context("notifying user that session is authenticated")?;

        sess.set_blocking(false);

        let mut sess = SessionWrap::with_ssh2(sess);
        self.request_loop(&mut sess)
    }

    /// Explicitly and directly connect to the requested host because
    /// neither libssh no libssh2 respect addressfamily, so we must
    /// handle it for ourselves.
    /// If proxy_command is set, then we execute that process for ourselves
    /// too, as proxy commands are not supported by libssh2 and are not supported
    /// on Windows in libssh.
    fn connect_to_host(
        &self,
        hostname: &str,
        port: u16,
        verbose: bool,
    ) -> anyhow::Result<(Socket, Option<KillOnDropChild>)> {
        match self.config.get("proxycommand").map(|s| s.as_str()) {
            Some("none") | None => {}
            Some(proxy_command) => {
                let mut cmd;
                if cfg!(windows) {
                    let comspec = std::env::var("COMSPEC").unwrap_or_else(|_| "cmd".to_string());
                    cmd = std::process::Command::new(comspec);
                    cmd.args(["/c", proxy_command]);
                } else {
                    cmd = std::process::Command::new("sh");
                    cmd.args(["-c", &format!("exec {}", proxy_command)]);
                }

                let (a, b) = socketpair()?;

                cmd.stdin(b.as_stdio()?);
                cmd.stdout(b.as_stdio()?);
                cmd.stderr(std::process::Stdio::inherit());
                let child = cmd
                    .spawn()
                    .with_context(|| format!("spawning ProxyCommand {}", proxy_command))?;

                #[cfg(unix)]
                unsafe {
                    use passfd::FdPassingExt;
                    use std::os::unix::io::{FromRawFd, IntoRawFd};

                    let raw = a.into_raw_fd();
                    let dest = match self.config.get("proxyusefdpass").map(|s| s.as_str()) {
                        Some("yes") => raw.recv_fd()?,
                        _ => raw,
                    };

                    return Ok((Socket::from_raw_fd(dest), Some(KillOnDropChild(child))));
                }
                #[cfg(windows)]
                unsafe {
                    use std::os::windows::io::{FromRawSocket, IntoRawSocket};
                    return Ok((
                        Socket::from_raw_socket(a.into_raw_socket()),
                        Some(KillOnDropChild(child)),
                    ));
                }
            }
        }

        let addr = (hostname, port)
            .to_socket_addrs()?
            .find(|addr| self.filter_sock_addr(addr))
            .with_context(|| format!("resolving address for {}", hostname))?;
        if verbose {
            log::info!("resolved {hostname}:{port} -> {addr:?}");
        }
        let sock = Socket::new(Domain::for_address(addr), Type::STREAM, None)?;
        if let Some(bind_addr) = self.config.get("bindaddress") {
            let bind_addr = (bind_addr.as_str(), 0)
                .to_socket_addrs()?
                .find(|addr| self.filter_sock_addr(addr))
                .with_context(|| format!("resolving bind address {bind_addr:?}"))?;
            if verbose {
                log::info!("binding to {bind_addr:?}");
            }
            sock.bind(&bind_addr.into())
                .with_context(|| format!("binding to {bind_addr:?}"))?;
        }

        let timeout = self.connect_timeout();
        sock.connect_timeout(&addr.into(), timeout)
            .with_context(|| {
                format!("Connecting to {hostname}:{port} ({addr:?}) within {timeout:?}")
            })?;
        set_transport_options(&sock);
        Ok((sock, None))
    }

    /// How long the TCP handshake above may take before the attempt is
    /// abandoned.
    ///
    /// Termob fork. `Socket::connect` carries no timeout of its own, so
    /// against a peer that silently drops SYNs — a firewall, a stale LAN
    /// address, a phone that has roamed off the network — it blocks for the OS
    /// retry budget: roughly 75s on macOS and 130s on Linux. The TLS transport
    /// already bounds this (`TlsDomainClient::connect_timeout`), but the SSH
    /// one did not, and the two meet: fetching TLS credentials over SSH runs
    /// this code on the FIRST connection of the picker's default mode. Leaving
    /// it unbounded meant the same address failed after ~75s on the first
    /// attempt and after 10s on the second, once credentials were cached.
    ///
    /// `connecttimeout` is OpenSSH's own option name, so a caller that already
    /// speaks ssh_config can set it. **A value of 0 selects the default here
    /// rather than "no limit"**, which is where OpenSSH would fall back to the
    /// system default: an unbounded connect is precisely the behaviour this
    /// exists to remove, so there is deliberately no way to ask for it back.
    fn connect_timeout(&self) -> Duration {
        const DEFAULT: Duration = Duration::from_secs(10);
        self.config
            .get("connecttimeout")
            .and_then(|v| v.parse::<u64>().ok())
            .map(Duration::from_secs)
            .filter(|d| !d.is_zero())
            .unwrap_or(DEFAULT)
    }

    /// Used to restrict to_socket_addrs results to the address
    /// family specified by the config
    fn filter_sock_addr(&self, addr: &std::net::SocketAddr) -> bool {
        match self.config.get("addressfamily").map(|s| s.as_str()) {
            Some("inet") => addr.is_ipv4(),
            Some("inet6") => addr.is_ipv6(),
            None | Some("any") | Some(_) => true,
        }
    }

    fn do_keepalive(&mut self, sess: &mut SessionWrap) -> anyhow::Result<()> {
        match sess {
            #[cfg(feature = "ssh2")]
            SessionWrap::Ssh2(_sess) => Ok(()),
            #[cfg(feature = "libssh-rs")]
            SessionWrap::LibSsh(sess) => {
                // We implement a very basic keep alive mechanism here;
                // every ServerAliveInterval seconds (if non-zero), we will
                // send an ignore packet.
                // Unlike the openssh client, we do not have a ServerAliveCountMax
                // limit (because it is not clear how we could correctly implement
                // that based on what we can see here in this crate), nor do we
                // explicitly trigger a disconnect if there is an error with
                // the ignore packet.
                if let Some(duration) = self.keep_alive {
                    if self.last_keep_alive.elapsed() >= duration {
                        log::trace!("sending keep alive");
                        self.last_keep_alive = Instant::now();
                        let ignore_me = [0x42; 128];
                        if let Err(err) = sess.sess.send_ignore(&ignore_me) {
                            log::warn!(
                                "Error sending IGNORE packet: {err:#}. Is peer disconnected?"
                            );
                        }
                    }
                }
                Ok(())
            }
        }
    }

    /// Termob fork: read whether the far end is keeping up, and for how long it
    /// has not been.
    ///
    /// Called every turn of the loop, which is at worst a quarter of a second
    /// apart — fine enough for a figure the user reads in seconds, and one
    /// `getsockopt` is far below what the loop already does per turn.
    ///
    /// The clock starts when bytes first go undelivered and is NOT restarted
    /// while they stay that way: what the reader wants is how long the far end
    /// has been silent, not how long the newest byte has waited. Any moment
    /// with nothing outstanding clears it, because the peer has just proved it
    /// is there.
    fn note_delivery(&mut self, sess: &SessionWrap) {
        let outstanding = match undelivered_bytes(sess.as_socket_descriptor()) {
            Some(bytes) => bytes,
            // The platform does not answer. Nothing is claimed rather than
            // "everything is fine": see `undelivered_bytes`.
            None => return,
        };
        if outstanding == 0 {
            self.undelivered_since = None;
        } else if self.undelivered_since.is_none() {
            self.undelivered_since = Some(Instant::now());
        }
        let waiting = self
            .undelivered_since
            .map_or(0, |since| since.elapsed().as_millis().min(u128::from(u64::MAX)) as u64);
        self.unanswered_ms.store(waiting, Ordering::Relaxed);
    }

    fn request_loop(&mut self, sess: &mut SessionWrap) -> anyhow::Result<()> {
        // Termob fork: authenticated, and from here on serving requests. This
        // is the one point that separates "being established" from
        // "established" — see `SessionInner::established`.
        self.established.store(true, Ordering::Relaxed);
        let mut sleep_delay = MIN_POLL_DELAY;

        loop {
            // Where an iteration's time goes, while the session still has no
            // channel.
            //
            // A request queued microseconds after this loop started was not
            // served for nearly two seconds, and from outside the loop that is
            // indistinguishable from a slow server. The window is bounded on
            // purpose: once a channel exists this is the hot path for every
            // keystroke, and it says nothing there that the echo latency does
            // not already say. The clock is not read at all outside that
            // window — `mark` answers zero — so the hot path pays a branch and
            // nothing else.
            let setting_up = self.channels.is_empty();
            let iteration = setting_up.then(Instant::now);
            let mark = |at: Option<Instant>| at.map_or(Duration::ZERO, |at| at.elapsed());

            self.note_delivery(sess);
            self.do_keepalive(sess)?;
            let keepalive_at = mark(iteration);
            // Termob fork: `tick_io` reports whether it actually moved bytes.
            // A single tick performs at most one read per channel, so when it
            // did move data the ssh library may still be holding more in its
            // own buffer -- and buffered bytes make the socket look quiet, so
            // `poll` would not report them. Polling with a zero timeout in
            // that case drains the backlog at full speed instead of one
            // chunk per timeout, which is what made heavy output arrive in
            // visible stutters.
            let moved_io = self.tick_io()?;
            let io_at = mark(iteration);
            self.drain_request_pipe();
            let drain_at = mark(iteration);
            self.dispatch_pending_requests(sess)?;
            let dispatch_at = mark(iteration);
            self.connect_pending_agent_forward_channels(sess);
            let forward_at = mark(iteration);

            // Termob fork: asked to close, so close — the channels are not
            // consulted. They belong to panes the caller has already finished
            // with, and waiting for them to drain makes the moment the
            // connection actually ends depend on how the last of their output
            // happened to fall.
            if self.shutdown_requested {
                log::debug!("Stopping session loop: the connection was closed by its owner");
                return Ok(());
            }

            if self.channels.is_empty() && self.session_was_dropped {
                log::trace!(
                    "Stopping session loop as there are no more channels and Session was dropped"
                );
                return Ok(());
            }

            // Termob fork: the transport has gone, so say so.
            //
            // Asked after the two deliberate endings above and before any
            // further work, so that a connection the owner closed is reported
            // as closed rather than as lost. The loop otherwise carried on
            // polling a socket the ssh library had already given up on: the
            // panes on it neither produced output nor died, and nothing on
            // screen said the connection had ended — a frozen terminal, which
            // is indistinguishable from a slow one.
            if !sess.is_connected() {
                anyhow::bail!("the connection to the host was lost");
            }

            // Termob fork: also watch the session socket for readability
            // whenever a channel has room for more output.
            //
            // `get_poll_flags` only reports what the ssh library is currently
            // *blocked* on; once a call completes it goes back to zero, and a
            // zero event mask means `poll` ignores the socket entirely. Remote
            // output arriving after that point was therefore not noticed until
            // the poll timed out -- one full timeout of latency on every
            // keystroke echo. Asking for POLLIN as well makes the loop
            // event-driven again.
            //
            // The "has room" condition matters: when every output buffer is
            // full we deliberately do not consume the socket, and an
            // unconditional POLLIN would then spin at 100% CPU on a socket we
            // refuse to read. In that state the pipe descriptors are already
            // polled for POLLOUT, so the loop still wakes as soon as the
            // consumer drains them.
            let mut session_events = sess.get_poll_flags();
            if self.has_room_for_channel_output() {
                session_events |= POLLIN;
            }
            let mut poll_array = vec![
                pollfd {
                    fd: self.sender_read.as_socket_descriptor(),
                    events: POLLIN,
                    revents: 0,
                },
                pollfd {
                    fd: sess.as_socket_descriptor(),
                    events: session_events,
                    revents: 0,
                },
            ];
            let mut mapping = vec![];

            for info in self.channels.values() {
                for (fd_num, state) in info.descriptors.iter().enumerate() {
                    if let Some(fd) = state.fd.as_ref() {
                        poll_array.push(pollfd {
                            fd: fd.as_socket_descriptor(),
                            events: if fd_num == 0 {
                                POLLIN
                            } else if !state.buf.is_empty() || info.exited {
                                POLLOUT
                            } else {
                                0
                            },
                            revents: 0,
                        });
                        mapping.push((info.channel_id, fd_num));
                    }
                }
            }

            // Termob fork: bounded backoff. Upstream doubled `sleep_delay`
            // forever (100ms, 200ms, ... minutes), and it is only reset when
            // some descriptor reports activity -- but data buffered inside the
            // ssh library never shows up as descriptor activity, so on a quiet
            // link the loop could sit on a multi-second timeout while output
            // was already available. The backoff still exists (an idle session
            // must not busy-poll) but it can no longer grow past
            // `MAX_POLL_DELAY`.
            let wait = if moved_io { Duration::ZERO } else { sleep_delay };
            let worked = mark(iteration);
            poll(&mut poll_array, Some(wait)).context("poll")?;
            if setting_up {
                log::debug!(
                    "setup loop iteration: keepalive {keepalive_at:?}, io {:?}, \
                     drain {:?}, dispatch {:?}, agent forward {:?}, poll {:?} \
                     (waited up to {wait:?})",
                    io_at - keepalive_at,
                    drain_at - io_at,
                    dispatch_at - drain_at,
                    forward_at - dispatch_at,
                    mark(iteration) - worked
                );
            }
            sleep_delay = if moved_io {
                MIN_POLL_DELAY
            } else {
                (sleep_delay + sleep_delay).min(MAX_POLL_DELAY)
            };

            for (idx, poll) in poll_array.iter().enumerate() {
                if poll.revents != 0 {
                    sleep_delay = MIN_POLL_DELAY;
                }
                if idx == 0 || idx == 1 {
                    // Dealt with at the top of the loop
                } else if poll.revents != 0 {
                    let (channel_id, fd_num) = mapping[idx - 2];
                    let info = self.channels.get_mut(&channel_id).unwrap();
                    let state = &mut info.descriptors[fd_num];
                    let fd = state.fd.as_mut().unwrap();

                    if fd_num == 0 {
                        // There's data we can read into the buffer
                        match read_into_buf(fd, &mut state.buf) {
                            Ok(_) => {}
                            Err(err) => {
                                log::debug!(
                                    "error reading from channel {channel_id} stdin pipe: {:#}",
                                    err
                                );
                                info.channel.close();
                                state.fd.take();
                            }
                        }
                    } else {
                        if info.exited && state.buf.is_empty() {
                            log::trace!("channel {channel_id} exited and we have no data to send to fd {fd_num}: close it!");
                            state.fd.take();
                        } else {
                            // We can write our buffered output
                            match write_from_buf(fd, &mut state.buf) {
                                Ok(_) => {}
                                Err(err) => {
                                    log::debug!(
                                        "error while writing to channel {} fd {}: {:#}",
                                        channel_id,
                                        fd_num,
                                        err
                                    );

                                    // Close it out
                                    state.fd.take();
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    /// Goal: if we have data to write to channels, try to send it.
    /// If we have room in our channel fd write buffers, try to fill it
    ///
    /// Termob fork: returns `true` when this tick actually moved bytes in
    /// either direction.
    ///
    /// Each tick performs at most one read per channel stream, so a `true`
    /// result means there may be more waiting inside the ssh library. Since
    /// buffered bytes do not make the socket readable, the caller polls with
    /// a zero timeout in that case and ticks again immediately, draining the
    /// backlog without waiting for a timeout that nothing will shorten.
    fn tick_io(&mut self) -> anyhow::Result<bool> {
        let mut moved = false;
        let mut dead = vec![];
        for (id, chan) in self.channels.iter_mut() {
            if chan.exit.is_some() {
                if let Some(status) = chan.channel.exit_status() {
                    log::trace!("channel {id} has exit status {status:?}");
                    chan.exited = true;
                    let exit = chan.exit.take().unwrap();
                    smol::block_on(exit.send(status)).ok();
                }
            }

            let stdin = &mut chan.descriptors[0];
            if stdin.fd.is_some() && !stdin.buf.is_empty() {
                let before = stdin.buf.len();
                if let Err(err) = write_from_buf(&mut chan.channel.writer(), &mut stdin.buf)
                    .context("writing to channel")
                {
                    log::trace!(
                        "Failed to write data to channel {} stdin: {:#}, closing pipe",
                        id,
                        err
                    );
                    stdin.fd.take();
                }
                moved |= stdin.buf.len() != before;
            }

            for (idx, out) in chan
                .descriptors
                .get_mut(1..)
                .unwrap()
                .iter_mut()
                .enumerate()
            {
                if out.fd.is_none() {
                    continue;
                }
                let current_len = out.buf.len();
                let room = out.buf.capacity() - current_len;
                if room == 0 {
                    continue;
                }
                match read_into_buf(&mut chan.channel.reader(idx), &mut out.buf) {
                    Ok(_) => {
                        moved |= out.buf.len() != current_len;
                    }
                    Err(err) => {
                        if out.buf.is_empty() {
                            log::trace!(
                                "Failed to read data from channel {} stream {}: {:#}, closing pipe",
                                id,
                                idx,
                                err
                            );
                            out.fd.take();
                        } else {
                            log::trace!(
                                "Failed to read data from channel {} stream {}: {:#}, but \
                                         still have some buffer to drain",
                                id,
                                idx,
                                err
                            );
                        }
                    }
                }
            }

            if chan
                .descriptors
                .iter()
                .all(|descriptor| descriptor.fd.is_none())
            {
                log::trace!("all descriptors on channel {} are closed", id);
                dead.push(*id);
            }
        }
        for id in dead {
            self.channels.remove(&id);
        }
        Ok(moved)
    }

    /// Termob fork: does any channel still have room for more remote output?
    ///
    /// Used to decide whether the session socket is worth polling for
    /// readability. When every output buffer is full the loop deliberately
    /// stops consuming the socket, and asking for POLLIN there would spin on
    /// a socket we refuse to drain; the per-descriptor POLLOUT wakeups still
    /// cover that state.
    fn has_room_for_channel_output(&self) -> bool {
        self.channels.values().any(|info| {
            info.descriptors
                .iter()
                .skip(1)
                .any(|state| state.fd.is_some() && state.buf.len() < state.buf.capacity())
        })
    }

    fn drain_request_pipe(&mut self) {
        let mut buf = [0u8; 16];
        let _ = self.sender_read.read(&mut buf);
    }

    fn dispatch_pending_requests(&mut self, sess: &mut SessionWrap) -> anyhow::Result<()> {
        while self.dispatch_one_request(sess)? {}
        Ok(())
    }

    fn dispatch_one_request(&mut self, sess: &mut SessionWrap) -> anyhow::Result<bool> {
        match self.rx_req.try_recv() {
            Err(TryRecvError::Closed) => anyhow::bail!("all clients are closed"),
            Err(TryRecvError::Empty) => Ok(false),
            Ok(req) => {
                sess.set_blocking(true);
                let res = match req {
                    SessionRequest::SessionDropped => {
                        self.session_was_dropped = true;
                        Ok(true)
                    }
                    // Termob fork: stop draining as well as stop looping —
                    // whatever else is queued was addressed to a connection the
                    // caller has already finished with.
                    SessionRequest::Shutdown => {
                        self.shutdown_requested = true;
                        Ok(false)
                    }
                    SessionRequest::NewPty(newpty, reply) => {
                        dispatch(reply, || self.new_pty(sess, newpty), "NewPty")
                    }
                    SessionRequest::ResizePty(resize, Some(reply)) => {
                        dispatch(reply, || self.resize_pty(resize), "resize_pty")
                    }
                    SessionRequest::ResizePty(resize, None) => {
                        if let Err(err) = self.resize_pty(resize) {
                            log::error!("error in resize_pty: {:#}", err);
                        }
                        Ok(true)
                    }
                    SessionRequest::Exec(exec, reply) => {
                        dispatch(reply, || self.exec(sess, exec), "exec")
                    }
                    SessionRequest::SignalChannel(info) => {
                        if let Err(err) = self.signal_channel(&info) {
                            log::error!("{:?} -> error: {:#}", info, err);
                        }
                        Ok(true)
                    }
                    SessionRequest::Sftp(SftpRequest::OpenWithMode(msg, reply)) => {
                        dispatch(reply, || self.open_with_mode(sess, &msg), "OpenWithMode")
                    }
                    SessionRequest::Sftp(SftpRequest::OpenDir(path, reply)) => {
                        dispatch(reply, || self.open_dir(sess, path), "OpenDir")
                    }
                    SessionRequest::Sftp(SftpRequest::File(FileRequest::Write(msg, reply))) => {
                        dispatch(
                            reply,
                            || {
                                let file = self
                                    .files
                                    .get_mut(&msg.file_id)
                                    .ok_or_else(|| anyhow!("invalid file_id"))?;
                                file.writer().write_all(&msg.data)?;
                                Ok(())
                            },
                            "write_file",
                        )
                    }
                    SessionRequest::Sftp(SftpRequest::File(FileRequest::Read(msg, reply))) => {
                        dispatch(
                            reply,
                            || {
                                let file = self
                                    .files
                                    .get_mut(&msg.file_id)
                                    .ok_or_else(|| anyhow!("invalid file_id"))?;

                                // TODO: Move this somewhere to avoid re-allocating buffer
                                let mut buf = vec![0u8; msg.max_bytes];
                                let n = file.reader().read(&mut buf)?;
                                buf.truncate(n);
                                Ok(buf)
                            },
                            "read_file",
                        )
                    }
                    SessionRequest::Sftp(SftpRequest::File(FileRequest::Close(file_id, reply))) => {
                        dispatch(
                            reply,
                            || {
                                self.files.remove(&file_id);
                                Ok(())
                            },
                            "close_file",
                        )
                    }
                    SessionRequest::Sftp(SftpRequest::Dir(DirRequest::Close(dir_id, reply))) => {
                        dispatch(
                            reply,
                            || {
                                self.dirs
                                    .remove(&dir_id)
                                    .ok_or_else(|| anyhow!("invalid dir_id"))?;
                                Ok(())
                            },
                            "close_dir",
                        )
                    }
                    SessionRequest::Sftp(SftpRequest::Dir(DirRequest::ReadDir(dir_id, reply))) => {
                        dispatch(
                            reply,
                            || {
                                let dir = self
                                    .dirs
                                    .get_mut(&dir_id)
                                    .ok_or_else(|| anyhow!("invalid dir_id"))?;
                                dir.read_dir()
                            },
                            "read_dir",
                        )
                    }
                    SessionRequest::Sftp(SftpRequest::File(FileRequest::Flush(file_id, reply))) => {
                        dispatch(
                            reply,
                            || {
                                let file = self
                                    .files
                                    .get_mut(&file_id)
                                    .ok_or_else(|| anyhow!("invalid file_id"))?;
                                file.writer().flush()?;
                                Ok(())
                            },
                            "flush_file",
                        )
                    }
                    SessionRequest::Sftp(SftpRequest::File(FileRequest::SetMetadata(
                        msg,
                        reply,
                    ))) => dispatch(
                        reply,
                        || {
                            let file = self
                                .files
                                .get_mut(&msg.file_id)
                                .ok_or_else(|| anyhow!("invalid file_id"))?;
                            file.set_metadata(msg.metadata)
                        },
                        "set_metadata_file",
                    ),
                    SessionRequest::Sftp(SftpRequest::File(FileRequest::Metadata(
                        file_id,
                        reply,
                    ))) => dispatch(
                        reply,
                        || {
                            let file = self
                                .files
                                .get_mut(&file_id)
                                .ok_or_else(|| anyhow!("invalid file_id"))?;
                            file.metadata()
                        },
                        "metadata_file",
                    ),
                    SessionRequest::Sftp(SftpRequest::File(FileRequest::Fsync(file_id, reply))) => {
                        dispatch(
                            reply,
                            || {
                                let file = self
                                    .files
                                    .get_mut(&file_id)
                                    .ok_or_else(|| anyhow!("invalid file_id"))?;
                                file.fsync()
                            },
                            "fsync",
                        )
                    }

                    SessionRequest::Sftp(SftpRequest::ReadDir(path, reply)) => {
                        dispatch(reply, || self.init_sftp(sess)?.read_dir(&path), "read_dir")
                    }
                    SessionRequest::Sftp(SftpRequest::CreateDir(msg, reply)) => dispatch(
                        reply,
                        || self.init_sftp(sess)?.create_dir(&msg.filename, msg.mode),
                        "create_dir",
                    ),
                    SessionRequest::Sftp(SftpRequest::RemoveDir(path, reply)) => dispatch(
                        reply,
                        || self.init_sftp(sess)?.remove_dir(&path),
                        "remove_dir",
                    ),
                    SessionRequest::Sftp(SftpRequest::Metadata(path, reply)) => {
                        dispatch(reply, || self.init_sftp(sess)?.metadata(&path), "metadata")
                    }
                    SessionRequest::Sftp(SftpRequest::SymlinkMetadata(path, reply)) => dispatch(
                        reply,
                        || self.init_sftp(sess)?.symlink_metadata(&path),
                        "symlink_metadata",
                    ),
                    SessionRequest::Sftp(SftpRequest::SetMetadata(msg, reply)) => dispatch(
                        reply,
                        || {
                            self.init_sftp(sess)?
                                .set_metadata(&msg.filename, msg.metadata)
                        },
                        "set_metadata",
                    ),
                    SessionRequest::Sftp(SftpRequest::Symlink(msg, reply)) => dispatch(
                        reply,
                        || self.init_sftp(sess)?.symlink(&msg.path, &msg.target),
                        "symlink",
                    ),
                    SessionRequest::Sftp(SftpRequest::ReadLink(path, reply)) => dispatch(
                        reply,
                        || self.init_sftp(sess)?.read_link(&path),
                        "read_link",
                    ),
                    SessionRequest::Sftp(SftpRequest::Canonicalize(path, reply)) => dispatch(
                        reply,
                        || self.init_sftp(sess)?.canonicalize(&path),
                        "canonicalize",
                    ),
                    SessionRequest::Sftp(SftpRequest::Rename(msg, reply)) => dispatch(
                        reply,
                        || self.init_sftp(sess)?.rename(&msg.src, &msg.dst, msg.opts),
                        "rename",
                    ),
                    SessionRequest::Sftp(SftpRequest::RemoveFile(path, reply)) => {
                        dispatch(reply, || self.init_sftp(sess)?.unlink(&path), "remove_file")
                    }
                };
                sess.set_blocking(false);
                res
            }
        }
    }

    fn connect_pending_agent_forward_channels(&mut self, sess: &mut SessionWrap) {
        fn process_one(sess: &mut SessionInner, channel: ChannelWrap) -> anyhow::Result<()> {
            let identity_agent = sess
                .identity_agent()
                .ok_or_else(|| anyhow!("no identity agent in config"))?;
            let mut fd = {
                use wezterm_uds::UnixStream;
                #[cfg(unix)]
                {
                    FileDescriptor::new(UnixStream::connect(&identity_agent)?)
                }
                #[cfg(windows)]
                unsafe {
                    use std::os::windows::io::{FromRawSocket, IntoRawSocket};
                    FileDescriptor::from_raw_socket(
                        UnixStream::connect(&identity_agent)?.into_raw_socket(),
                    )
                }
            };
            fd.set_non_blocking(true)?;

            let read_from_agent = fd;
            let write_to_agent = read_from_agent.try_clone()?;
            let channel_id = sess.next_channel_id;
            sess.next_channel_id += 1;
            let info = ChannelInfo {
                channel_id,
                channel,
                exit: None,
                exited: false,
                descriptors: [
                    DescriptorState {
                        fd: Some(read_from_agent),
                        buf: VecDeque::with_capacity(8192),
                    },
                    DescriptorState {
                        fd: Some(write_to_agent),
                        buf: VecDeque::with_capacity(8192),
                    },
                    DescriptorState {
                        fd: None,
                        buf: VecDeque::with_capacity(8192),
                    },
                ],
            };
            sess.channels.insert(channel_id, info);
            Ok(())
        }
        while let Some(channel) = sess.accept_agent_forward() {
            if let Err(err) = process_one(self, channel) {
                log::error!("error connecting agent forward: {:#}", err);
            }
        }
    }

    pub fn signal_channel(&mut self, info: &SignalChannel) -> anyhow::Result<()> {
        let chan_info = self
            .channels
            .get_mut(&info.channel)
            .ok_or_else(|| anyhow::anyhow!("invalid channel id {}", info.channel))?;
        log::trace!("send SIG{} to channel {}", info.signame, info.channel);
        chan_info.channel.send_signal(info.signame)?;
        Ok(())
    }

    pub fn exec(&mut self, sess: &mut SessionWrap, exec: Exec) -> anyhow::Result<ExecResult> {
        let mut channel = sess.open_session()?;

        if let Some("yes") = self.config.get("forwardagent").map(|s| s.as_str()) {
            if self.identity_agent().is_some() {
                if let Err(err) = channel.request_auth_agent_forwarding() {
                    log::error!("Failed to request agent forwarding: {:#}", err);
                }
            }
        }

        if let Some(env) = &exec.env {
            for (key, val) in env {
                if let Err(err) = channel.request_env(key, val) {
                    // Depending on the server configuration, a given
                    // setenv request may not succeed, but that doesn't
                    // prevent the connection from being set up.
                    log::warn!(
                        "ssh: setenv {}={} failed: {}. \
                         Check the AcceptEnv setting on the ssh server side.",
                        key,
                        val,
                        err
                    );
                }
            }
        }

        channel.request_exec(&exec.command_line)?;

        let channel_id = self.next_channel_id;
        self.next_channel_id += 1;

        let (write_to_stdin, mut read_from_stdin) = socketpair()?;
        let (mut write_to_stdout, read_from_stdout) = socketpair()?;
        let (mut write_to_stderr, read_from_stderr) = socketpair()?;

        read_from_stdin.set_non_blocking(true)?;
        write_to_stdout.set_non_blocking(true)?;
        write_to_stderr.set_non_blocking(true)?;

        let (exit_tx, exit_rx) = bounded(1);

        let child = SshChildProcess {
            channel: channel_id,
            tx: None,
            exit: exit_rx,
            exited: None,
        };

        let result = ExecResult {
            stdin: write_to_stdin,
            stdout: read_from_stdout,
            stderr: read_from_stderr,
            child,
        };

        let info = ChannelInfo {
            channel_id,
            channel,
            exit: Some(exit_tx),
            exited: false,
            descriptors: [
                DescriptorState {
                    fd: Some(read_from_stdin),
                    buf: VecDeque::with_capacity(8192),
                },
                DescriptorState {
                    fd: Some(write_to_stdout),
                    buf: VecDeque::with_capacity(8192),
                },
                DescriptorState {
                    fd: Some(write_to_stderr),
                    buf: VecDeque::with_capacity(8192),
                },
            ],
        };

        self.channels.insert(channel_id, info);

        Ok(result)
    }

    /// Open a handle to a file.
    pub fn open_with_mode(
        &mut self,
        sess: &mut SessionWrap,
        msg: &OpenWithMode,
    ) -> SftpChannelResult<File> {
        let ssh_file = self.init_sftp(sess)?.open(&msg.filename, msg.opts)?;

        let file_id = self.next_file_id;
        self.next_file_id += 1;

        let file = File::new(file_id);

        self.files.insert(file_id, ssh_file);
        Ok(file)
    }

    /// Helper to open a directory for reading its contents.
    pub fn open_dir(
        &mut self,
        sess: &mut SessionWrap,
        path: Utf8PathBuf,
    ) -> SftpChannelResult<Dir> {
        let ssh_dir = self.init_sftp(sess)?.open_dir(&path)?;

        let dir_id = self.next_file_id;
        self.next_file_id += 1;

        let dir = Dir::new(dir_id);

        self.dirs.insert(dir_id, ssh_dir);
        Ok(dir)
    }

    /// Initialize the sftp channel if not already created, returning a mutable reference to it
    fn init_sftp<'a>(&mut self, sess: &'a mut SessionWrap) -> SftpChannelResult<&'a mut SftpWrap> {
        match sess {
            #[cfg(feature = "ssh2")]
            SessionWrap::Ssh2(sess) => {
                if sess.sftp.is_none() {
                    sess.sftp = Some(SftpWrap::Ssh2(sess.sess.sftp()?));
                }
                Ok(sess.sftp.as_mut().expect("sftp should have been set above"))
            }

            #[cfg(feature = "libssh-rs")]
            SessionWrap::LibSsh(sess) => {
                if sess.sftp.is_none() {
                    sess.sftp = Some(SftpWrap::LibSsh(sess.sess.sftp()?));
                }
                Ok(sess.sftp.as_mut().expect("sftp should have been set above"))
            }
        }
    }

    pub fn identity_agent(&self) -> Option<String> {
        self.config
            .get("identityagent")
            .map(|s| s.to_owned())
            .or_else(|| std::env::var("SSH_AUTH_SOCK").ok())
    }
}

fn write_from_buf<W: Write>(w: &mut W, buf: &mut VecDeque<u8>) -> std::io::Result<()> {
    match w.write(buf.make_contiguous()) {
        Ok(len) => {
            buf.drain(0..len);
            Ok(())
        }
        Err(err) => {
            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(());
            }
            Err(err)
        }
    }
}

fn read_into_buf<R: Read>(r: &mut R, buf: &mut VecDeque<u8>) -> std::io::Result<()> {
    let current_len = buf.len();
    buf.resize(buf.capacity(), 0);
    let target_buf = &mut buf.make_contiguous()[current_len..];
    match r.read(target_buf) {
        Ok(len) => {
            buf.resize(current_len + len, 0);
            if len == 0 {
                Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "EOF",
                ))
            } else {
                Ok(())
            }
        }
        Err(err) => {
            buf.resize(current_len, 0);

            if err.kind() == std::io::ErrorKind::WouldBlock {
                return Ok(());
            }
            Err(err)
        }
    }
}

/// A little helper to ensure that the Result returned by `f()`
/// is routed via a Sender
fn dispatch<T, F>(reply: Sender<T>, f: F, what: &str) -> anyhow::Result<bool>
where
    F: FnOnce() -> T,
    T: Send + Sync + 'static,
{
    if let Err(err) = reply.try_send(f()) {
        // Termob fork: at `debug`, because this says nothing about the
        // operation.
        //
        // The reply channel is created per request and holds one slot, so the
        // only way this fails is that whoever asked has since gone away — an
        // sftp handle closed as its owner was torn down reaches here every
        // time. The work was still done; what is missing is somebody to tell.
        // Reported as an error, it named the operation ("close_file") and read
        // as that operation having failed.
        log::debug!("{}: nothing is waiting for the answer: {:#}", what, err);
    }
    Ok(true)
}

/// A little helper to ensure the Child process is killed on Drop.
struct KillOnDropChild(std::process::Child);

impl Drop for KillOnDropChild {
    fn drop(&mut self) {
        if let Err(err) = self.0.kill() {
            log::error!("Error killing ProxyCommand: {}", err);
        }
        if let Err(err) = self.0.wait() {
            log::error!("Error waiting for ProxyCommand to finish: {}", err);
        }
    }
}
