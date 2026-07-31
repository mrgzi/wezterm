use crate::domain::{ClientDomain, ClientDomainConfig};
use crate::pane::ClientPane;
use anyhow::{anyhow, bail, Context};
use async_ossl::AsyncSslStream;
use async_trait::async_trait;
use codec::*;
use config::{configuration, SshDomain, TlsDomainClient, UnixDomain, UnixTarget};
use filedescriptor::FileDescriptor;
use futures::FutureExt;
use mux::client::ClientId;
use mux::connui::ConnectionUI;
use mux::domain::DomainId;
use mux::pane::PaneId;
use mux::ssh::ssh_connect_with_ui;
use mux::Mux;
use mux::MuxNotification;
use openssl::pkey::PKey;
use openssl::ssl::{SslConnector, SslMethod};
use openssl::x509::X509;
use portable_pty::Child;
use smol::channel::{bounded, unbounded, Receiver, Sender};
use smol::prelude::*;
use smol::{block_on, Async};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::marker::Unpin;
use std::net::{TcpStream, ToSocketAddrs};
#[cfg(unix)]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
#[cfg(unix)]
use std::os::unix::process::CommandExt;
#[cfg(windows)]
use std::os::windows::io::{AsRawSocket, AsSocket, BorrowedSocket, RawSocket};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;
use thiserror::Error;
use wezterm_uds::UnixStream;

#[derive(Error, Debug)]
#[error("Timeout")]
struct Timeout;

#[derive(Error, Debug)]
#[error("ChannelSendError")]
struct ChannelSendError;

enum ReaderMessage {
    SendPdu {
        pdu: Pdu,
        promise: Sender<anyhow::Result<Pdu>>,
    },
    Readable,
    /// Termob fork: the keepalive timer fired (see client_thread_async).
    KeepaliveTick,
}

#[derive(Clone)]
pub struct Client {
    sender: Sender<ReaderMessage>,
    local_domain_id: Option<DomainId>,
    pub client_id: ClientId,
    client_domain_config: ClientDomainConfig,
    pub is_reconnectable: bool,
    pub is_local: bool,
    /// Termob fork: is the transport currently carrying traffic?
    ///
    /// `Domain::state()` cannot answer this. It reports `Attached` for as long
    /// as the domain holds a `ClientInner`, which stays true throughout a
    /// disconnect: the reader thread drops into the reconnect loop but the
    /// domain is untouched. A frontend that wants to tell the user "this tab
    /// lost its connection" therefore has nothing to read.
    ///
    /// Set to `false` when `client_thread` returns an error, back to `true`
    /// once a reconnect succeeds, and left `false` when the loop gives up.
    /// Owned by the reader thread; readers only observe.
    connection_live: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
#[error(
    "Please install the same version of wezterm on both the client and server!\n\
     The server version is {} (codec version {}),\n\
     which is not compatible with our version \n\
     {} (codec version {}).",
    version,
    codec_vers,
    config::wezterm_version(),
    CODEC_VERSION
)]
pub struct IncompatibleVersionError {
    pub version: String,
    pub codec_vers: usize,
}

macro_rules! rpc {
    ($method_name:ident, $request_type:ident, $response_type:ident) => {
        pub async fn $method_name(&self, pdu: $request_type) -> anyhow::Result<$response_type> {
            let start = std::time::Instant::now();
            let result = self.send_pdu(Pdu::$request_type(pdu)).await;
            let elapsed = start.elapsed();
            metrics::histogram!("rpc", "method" => stringify!($method_name)).record(elapsed);
            metrics::counter!("rpc.count", "method" => stringify!($method_name)).increment(1);
            match result {
                Ok(Pdu::$response_type(res)) => Ok(res),
                Ok(_) => bail!("unexpected response {:?}", result),
                Err(err) => Err(err),
            }
        }
    };

    // This variant allows omitting the request parameter; this is useful
    // in the case where the struct is empty and present only for the purpose
    // of typing the request.
    ($method_name:ident, $request_type:ident=(), $response_type:ident) => {
        #[allow(dead_code)]
        pub async fn $method_name(&self) -> anyhow::Result<$response_type> {
            let start = std::time::Instant::now();
            let result = self.send_pdu(Pdu::$request_type($request_type{})).await;
            let elapsed = start.elapsed();
            metrics::histogram!("rpc", "method" => stringify!($method_name)).record(elapsed);
            metrics::counter!("rpc.count", "method" => stringify!($method_name)).increment(1);
            match result {
                Ok(Pdu::$response_type(res)) => Ok(res),
                Ok(_) => bail!("unexpected response {:?}", result),
                Err(err) => Err(err),
            }
        }
    };
}

fn process_unilateral_inner(pane_id: PaneId, local_domain_id: DomainId, decoded: DecodedPdu) {
    promise::spawn::spawn(async move {
        process_unilateral_inner_async(pane_id, local_domain_id, decoded).await?;
        Ok::<(), anyhow::Error>(())
    })
    .detach();
}

async fn process_unilateral_inner_async(
    pane_id: PaneId,
    local_domain_id: DomainId,
    decoded: DecodedPdu,
) -> anyhow::Result<()> {
    let mux = match Mux::try_get() {
        Some(mux) => mux,
        None => {
            // This can happen for some client scenarios; it is ok to ignore it.
            return Ok(());
        }
    };

    let client_domain = mux
        .get_domain(local_domain_id)
        .ok_or_else(|| anyhow!("no such domain {}", local_domain_id))?;
    let client_domain = client_domain
        .downcast_ref::<ClientDomain>()
        .ok_or_else(|| anyhow!("domain {} is not a ClientDomain instance", local_domain_id))?;

    // If we get a push for a pane that we don't yet know about,
    // it means that some other client has manipulated the mux
    // topology; we need to re-sync.
    let local_pane_id = match client_domain.remote_to_local_pane_id(pane_id) {
        Some(p) => p,
        None => {
            log::debug!("got {decoded:?}, pane not found locally, resync");
            client_domain.resync().await?;
            client_domain
                .remote_to_local_pane_id(pane_id)
                .ok_or_else(|| {
                    anyhow!("remote pane id {} does not have a local pane id", pane_id)
                })?
        }
    };

    let pane = match mux.get_pane(local_pane_id) {
        Some(p) => p,
        None => {
            log::debug!("got {decoded:?}, but local pane {local_pane_id} no longer exists; resync");
            client_domain.resync().await?;

            let local_pane_id =
                client_domain
                    .remote_to_local_pane_id(pane_id)
                    .ok_or_else(|| {
                        anyhow!("remote pane id {} does not have a local pane id", pane_id)
                    })?;

            mux.get_pane(local_pane_id)
                .ok_or_else(|| anyhow!("local pane {local_pane_id} not found"))?
        }
    };
    let client_pane = pane.downcast_ref::<ClientPane>().ok_or_else(|| {
        log::error!(
            "received unilateral PDU for pane {} which is \
                     not an instance of ClientPane: {:?}",
            local_pane_id,
            decoded.pdu
        );
        anyhow!(
            "received unilateral PDU for pane {} which is \
                     not an instance of ClientPane: {:?}",
            local_pane_id,
            decoded.pdu
        )
    })?;
    client_pane.process_unilateral(decoded.pdu).await
}

fn process_unilateral(
    local_domain_id: Option<DomainId>,
    decoded: DecodedPdu,
) -> anyhow::Result<()> {
    let local_domain_id = match local_domain_id {
        Some(id) => id,
        None => {
            // FIXME: We currently get a bunch of these; we'll need
            // to do something to advise the server when we want them.
            // For now, we just ignore them.
            log::trace!(
                "client doesn't have a real local domain, \
                 so unilateral message cannot be processed by it"
            );
            return Ok(());
        }
    };
    match &decoded.pdu {
        Pdu::WindowWorkspaceChanged(WindowWorkspaceChanged {
            window_id,
            workspace,
        }) => {
            let window_id = *window_id;
            let workspace = workspace.to_string();
            promise::spawn::spawn_into_main_thread(async move {
                let mux = Mux::try_get().ok_or_else(|| anyhow!("no more mux"))?;
                let client_domain = mux
                    .get_domain(local_domain_id)
                    .ok_or_else(|| anyhow!("no such domain {}", local_domain_id))?;
                let client_domain =
                    client_domain
                        .downcast_ref::<ClientDomain>()
                        .ok_or_else(|| {
                            anyhow!("domain {} is not a ClientDomain instance", local_domain_id)
                        })?;

                let local_window_id = client_domain
                    .remote_to_local_window_id(window_id)
                    .ok_or_else(|| anyhow!("no local window for remote window id {}", window_id))?;
                if let Some(mut window) = mux.get_window_mut(local_window_id) {
                    window.set_workspace(&workspace);
                }

                anyhow::Result::<()>::Ok(())
            })
            .detach();

            return Ok(());
        }
        Pdu::WindowTitleChanged(WindowTitleChanged { window_id, title }) => {
            let title = title.to_string();
            let window_id = *window_id;
            promise::spawn::spawn_into_main_thread(async move {
                let mux = Mux::try_get().ok_or_else(|| anyhow!("no more mux"))?;
                let client_domain = mux
                    .get_domain(local_domain_id)
                    .ok_or_else(|| anyhow!("no such domain {}", local_domain_id))?;
                let client_domain =
                    client_domain
                        .downcast_ref::<ClientDomain>()
                        .ok_or_else(|| {
                            anyhow!("domain {} is not a ClientDomain instance", local_domain_id)
                        })?;

                client_domain.process_remote_window_title_change(window_id, title);
                anyhow::Result::<()>::Ok(())
            })
            .detach();
            return Ok(());
        }
        Pdu::RenameWorkspace(RenameWorkspace {
            old_workspace,
            new_workspace,
        }) => {
            let old_workspace = old_workspace.to_string();
            let new_workspace = new_workspace.to_string();
            promise::spawn::spawn_into_main_thread(async move {
                let mux = Mux::try_get().ok_or_else(|| anyhow!("no more mux"))?;
                log::debug!("got a rename {old_workspace} -> {new_workspace}");
                mux.rename_workspace(&old_workspace, &new_workspace);
                anyhow::Result::<()>::Ok(())
            })
            .detach();
            return Ok(());
        }
        Pdu::TabTitleChanged(TabTitleChanged { tab_id, title }) => {
            let title = title.to_string();
            let tab_id = *tab_id;
            promise::spawn::spawn_into_main_thread(async move {
                let mux = Mux::try_get().ok_or_else(|| anyhow!("no more mux"))?;
                let client_domain = mux
                    .get_domain(local_domain_id)
                    .ok_or_else(|| anyhow!("no such domain {}", local_domain_id))?;
                let client_domain =
                    client_domain
                        .downcast_ref::<ClientDomain>()
                        .ok_or_else(|| {
                            anyhow!("domain {} is not a ClientDomain instance", local_domain_id)
                        })?;

                client_domain.process_remote_tab_title_change(tab_id, title);
                anyhow::Result::<()>::Ok(())
            })
            .detach();
            return Ok(());
        }
        Pdu::TabResized(_) | Pdu::TabAddedToWindow(_) => {
            log::trace!("resync due to {:?}", decoded.pdu);
            promise::spawn::spawn_into_main_thread(async move {
                let mux = Mux::try_get().ok_or_else(|| anyhow!("no more mux"))?;
                let client_domain = mux
                    .get_domain(local_domain_id)
                    .ok_or_else(|| anyhow!("no such domain {}", local_domain_id))?;
                let client_domain =
                    client_domain
                        .downcast_ref::<ClientDomain>()
                        .ok_or_else(|| {
                            anyhow!("domain {} is not a ClientDomain instance", local_domain_id)
                        })?;

                client_domain.resync().await
            })
            .detach();

            return Ok(());
        }
        // Termob fork: opaque termob-proto message from the server. Relay it
        // verbatim to termob's mux subscriber as `MuxNotification::TermobChannel`.
        // We do NOT route through `process_unilateral_inner` (remote→local pane
        // map) because the payload carries termob's own remote pane id and may
        // be connection-level (pane_id == 0, e.g. a state delta push); the mux
        // layer must not interpret it.
        Pdu::TermobChannelResponse(TermobChannelResponse {
            pane_id,
            call_id,
            payload,
        }) => {
            let pane_id = *pane_id;
            let call_id = *call_id;
            let payload = std::sync::Arc::new(payload.clone());
            promise::spawn::spawn_into_main_thread(async move {
                if let Some(mux) = Mux::try_get() {
                    mux.notify(MuxNotification::TermobChannel {
                        pane_id,
                        call_id,
                        payload,
                        domain: Some(local_domain_id),
                    });
                }
            })
            .detach();
            return Ok(());
        }
        _ => {}
    }

    if let Some(pane_id) = decoded.pdu.pane_id() {
        promise::spawn::spawn_into_main_thread(async move {
            process_unilateral_inner(pane_id, local_domain_id, decoded)
        })
        .detach();
    } else {
        bail!("don't know how to handle {:?}", decoded);
    }
    Ok(())
}

#[derive(Error, Debug, Clone, PartialEq, Eq)]
enum NotReconnectableError {
    #[error("Client was destroyed")]
    ClientWasDestroyed,
}

fn client_thread(
    reconnectable: &mut Reconnectable,
    local_domain_id: Option<DomainId>,
    rx: &mut Receiver<ReaderMessage>,
) -> anyhow::Result<()> {
    block_on(client_thread_async(reconnectable, local_domain_id, rx))
}

async fn client_thread_async(
    reconnectable: &mut Reconnectable,
    local_domain_id: Option<DomainId>,
    rx: &mut Receiver<ReaderMessage>,
) -> anyhow::Result<()> {
    let mut next_serial = 1u64;

    struct Promises {
        map: HashMap<u64, Sender<anyhow::Result<Pdu>>>,
    }

    impl Promises {
        fn fail_all(&mut self, reason: &str) {
            log::trace!("failing all promises: {}", reason);
            for (_, promise) in self.map.drain() {
                let _ = promise.try_send(Err(anyhow!("{}", reason)));
            }
        }
    }

    impl Drop for Promises {
        fn drop(&mut self) {
            self.fail_all("Client was destroyed");
        }
    }
    let mut promises = Promises {
        map: HashMap::new(),
    };

    let mut stream = reconnectable.take_stream().unwrap();

    // Termob fork: application-level keepalive. The socket read/write
    // timeouts configured at connect time are dead once the stream is
    // switched to non-blocking (Async::new), and there is no OS keepalive,
    // so a silent half-close (mobile roaming, NAT timeout) would hang this
    // loop forever waiting for readability. When the connection has been
    // idle for PING_INTERVAL we send a Ping; if nothing at all arrives
    // within PONG_TIMEOUT after that, the connection is declared dead so
    // the reconnect logic in Client::new can take over. Any inbound data
    // counts as liveness (cheaper than tracking the specific Pong).
    const PING_INTERVAL: Duration = Duration::from_secs(15);
    const PONG_TIMEOUT: Duration = Duration::from_secs(10);
    // Local (unix-socket) connections can't suffer a roaming half-close and
    // aren't reconnectable anyway — don't wake up every 15s for them.
    let keepalive_enabled = !reconnectable.is_local();
    let mut last_activity = std::time::Instant::now();
    // `awaiting_pong`: a keepalive ping went out and no data of any kind has
    // arrived since — the next timer expiry declares the connection dead.
    let mut awaiting_pong = false;
    // Serials of keepalive pings whose Pong hasn't arrived yet. Keepalive
    // responses are deliberately NOT routed through `promises.map`: a promise
    // whose receiver has gone away is treated as ClientWasDestroyed by the
    // dispatch below, so parking a ping there would turn a merely *delayed*
    // Pong into a permanent, non-reconnectable teardown. Instead the ping is
    // sent bare and its response is consumed here by serial. Entries are
    // pruned when answered; responses arrive in order on the single stream,
    // so consuming serial S also retires every older outstanding ping.
    let mut outstanding_pings: Vec<u64> = Vec::new();

    loop {
        let rx_msg = rx.recv();
        let wait_for_read = stream
            .wait_for_readable()
            .map(|_| Ok(ReaderMessage::Readable));
        let idle_budget = if awaiting_pong {
            PONG_TIMEOUT
        } else {
            PING_INTERVAL
        };
        let deadline = last_activity + idle_budget;
        let keepalive_timer = async {
            if keepalive_enabled {
                smol::Timer::at(deadline).await;
            } else {
                smol::future::pending::<()>().await;
            }
            Ok(ReaderMessage::KeepaliveTick)
        };

        match smol::future::or(smol::future::or(rx_msg, wait_for_read), keepalive_timer).await {
            Ok(ReaderMessage::KeepaliveTick) => {
                if awaiting_pong {
                    promises.fail_all("connection timed out (no response to keepalive ping)");
                    bail!(
                        "connection timed out: no data received for {:?} after keepalive ping",
                        PONG_TIMEOUT
                    );
                }
                let serial = next_serial;
                next_serial += 1;
                outstanding_pings.push(serial);
                awaiting_pong = true;
                Pdu::Ping(Ping {})
                    .encode_async(&mut stream, serial)
                    .await
                    .context("encoding keepalive ping")?;
                stream.flush().await.context("flushing keepalive ping")?;
                // Restart the idle clock so PONG_TIMEOUT is measured from the
                // moment the ping was sent.
                last_activity = std::time::Instant::now();
            }
            Ok(ReaderMessage::SendPdu { pdu, promise }) => {
                let serial = next_serial;
                next_serial += 1;
                promises.map.insert(serial, promise);

                pdu.encode_async(&mut stream, serial)
                    .await
                    .context("encoding a PDU to send to the server")?;
                stream.flush().await.context("flushing PDU to server")?;
            }
            Ok(ReaderMessage::Readable) => {
                // Any inbound data proves the connection is alive.
                last_activity = std::time::Instant::now();
                awaiting_pong = false;
                match Pdu::decode_async(&mut stream, Some(next_serial)).await {
                    Ok(decoded) => {
                        log::debug!(
                            "decoded serial {} {}",
                            decoded.serial,
                            decoded.pdu.pdu_name()
                        );
                        if let Some(pos) = outstanding_pings
                            .iter()
                            .position(|serial| *serial == decoded.serial)
                        {
                            // A keepalive answered. Responses arrive in order,
                            // so any older outstanding pings will never be
                            // answered separately — retire them too.
                            outstanding_pings.drain(..=pos);
                        } else if decoded.serial == 0 {
                            process_unilateral(local_domain_id, decoded)
                                .context("processing unilateral PDU from server")
                                .map_err(|e| {
                                    log::error!("process_unilateral: {:?}", e);
                                    e
                                })?;
                        } else if let Some(promise) = promises.map.remove(&decoded.serial) {
                            if promise.try_send(Ok(decoded.pdu)).is_err() {
                                return Err(NotReconnectableError::ClientWasDestroyed.into());
                            }
                        } else {
                            let reason =
                                format!("got serial {:?} without a corresponding promise", decoded);
                            promises.fail_all(&reason);
                            anyhow::bail!("{}", reason);
                        }
                    }
                    Err(err) => {
                        let reason = format!("Error while decoding response pdu: {:#}", err);
                        log::error!("{}", reason);
                        promises.fail_all(&reason);
                        return Err(err).context("Error while decoding response pdu");
                    }
                }
            }
            Err(_) => {
                return Err(NotReconnectableError::ClientWasDestroyed.into());
            }
        }
    }
}

pub fn unix_connect_with_retry(
    target: &UnixTarget,
    just_spawned: bool,
    max_attempts: Option<u64>,
) -> anyhow::Result<UnixStream> {
    let mut error = None;

    if just_spawned {
        std::thread::sleep(std::time::Duration::from_millis(200));
    }

    let max_attempts = max_attempts.unwrap_or(10);

    for iter in 0..max_attempts {
        if iter > 0 {
            std::thread::sleep(std::time::Duration::from_millis(iter * 50));
        }
        match target {
            UnixTarget::Socket(path) => match UnixStream::connect(path) {
                Ok(stream) => return Ok(stream),
                Err(err) => {
                    error =
                        Some(Err(err).with_context(|| format!("connecting to {}", path.display())))
                }
            },
            UnixTarget::Proxy(argv) => {
                let mut cmd = std::process::Command::new(&argv[0]);
                cmd.args(&argv[1..]);

                let (a, b) = filedescriptor::socketpair()?;

                cmd.stdin(b.as_stdio()?);
                cmd.stdout(b.as_stdio()?);
                cmd.stderr(std::process::Stdio::inherit());
                let mut child = cmd
                    .spawn()
                    .with_context(|| format!("spawning proxy command {:?}", cmd))?;

                error.take();

                // Grace period to detect whether connection failed
                for _ in 0..5 {
                    std::thread::sleep(std::time::Duration::from_millis(10));
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            error = Some(Err(anyhow!(
                                "{:?} exited already with status {:?}",
                                cmd,
                                status
                            )));
                            continue;
                        }
                        Ok(None) => {
                            error.take();
                        }
                        Err(err) => {
                            error =
                                Some(Err(err).context(format!("spawning proxy command {:?}", cmd)));
                            continue;
                        }
                    }
                }

                if error.is_none() {
                    #[cfg(unix)]
                    unsafe {
                        use std::os::unix::io::{FromRawFd, IntoRawFd};
                        return Ok(UnixStream::from_raw_fd(a.into_raw_fd()));
                    }
                    #[cfg(windows)]
                    unsafe {
                        use std::os::windows::io::{FromRawSocket, IntoRawSocket};
                        return Ok(UnixStream::from_raw_socket(a.into_raw_socket()));
                    }
                }
            }
        }
    }

    error.expect("only get here after at least one unix fail")
}

#[async_trait(?Send)]
pub trait AsyncReadAndWrite: Unpin + AsyncRead + AsyncWrite + std::fmt::Debug + Send {
    async fn wait_for_readable(&self) -> anyhow::Result<()>;
}

#[async_trait(?Send)]
impl<T> AsyncReadAndWrite for Async<T>
where
    T: std::fmt::Debug,
    T: std::io::Write,
    T: std::io::Read,
    T: Send,
    T: async_io::IoSafe,
{
    async fn wait_for_readable(&self) -> anyhow::Result<()> {
        Ok(self.readable().await?)
    }
}

#[derive(Debug)]
struct Reconnectable {
    config: ClientDomainConfig,
    stream: Option<Box<dyn AsyncReadAndWrite>>,
    tls_creds: Option<GetTlsCredsResponse>,
}

struct SshStream {
    stdin: FileDescriptor,
    stdout: FileDescriptor,
}

unsafe impl async_io::IoSafe for SshStream {}

impl std::fmt::Debug for SshStream {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        write!(fmt, "SshStream {{...}}")
    }
}

#[cfg(unix)]
impl AsFd for SshStream {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.stdout.as_fd()
    }
}

#[cfg(unix)]
impl AsRawFd for SshStream {
    fn as_raw_fd(&self) -> RawFd {
        self.stdout.as_raw_fd()
    }
}

#[cfg(windows)]
impl AsRawSocket for SshStream {
    fn as_raw_socket(&self) -> RawSocket {
        self.stdout.as_raw_socket()
    }
}

#[cfg(windows)]
impl AsSocket for SshStream {
    fn as_socket(&self) -> BorrowedSocket {
        self.stdout.as_socket()
    }
}

impl Read for SshStream {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        self.stdout.read(buf)
    }
}

impl Write for SshStream {
    fn write(&mut self, buf: &[u8]) -> Result<usize, std::io::Error> {
        self.stdin.write(buf)
    }
    fn flush(&mut self) -> Result<(), std::io::Error> {
        self.stdin.flush()
    }
}

impl Reconnectable {
    fn new(config: ClientDomainConfig, stream: Option<Box<dyn AsyncReadAndWrite>>) -> Self {
        Self {
            config,
            stream,
            tls_creds: None,
        }
    }

    fn tls_creds_path(&self) -> anyhow::Result<PathBuf> {
        let path = config::pki_dir()?.join(escape_for_directory_name(self.config.name()));
        std::fs::create_dir_all(&path)?;
        Ok(path)
    }

    fn tls_creds_ca_path(&self) -> anyhow::Result<PathBuf> {
        Ok(self.tls_creds_path()?.join("ca.pem"))
    }

    fn tls_creds_cert_path(&self) -> anyhow::Result<PathBuf> {
        Ok(self.tls_creds_path()?.join("cert.pem"))
    }

    fn take_stream(&mut self) -> Option<Box<dyn AsyncReadAndWrite>> {
        self.stream.take()
    }

    fn is_local(&mut self) -> bool {
        matches!(&self.config, ClientDomainConfig::Unix(_))
    }

    fn reconnectable(&mut self) -> bool {
        match &self.config {
            // It doesn't make sense to reconnect to a unix socket; we only
            // get disconnected it it dies, so respawning it would not preserve
            // the set of tabs and we'd have confusing and inconsistent state
            ClientDomainConfig::Unix(_) => false,
            ClientDomainConfig::Tls(_) => true,
            // It *does* make sense to reconnect with an ssh session, but we
            // need to grow some smarts about whether the disconnect was because
            // we sent CTRL-D to close the last session, or whether it was a network
            // level disconnect, because we will otherwise throw up authentication
            // dialogs that would be annoying
            ClientDomainConfig::Ssh(_) => false,
        }
    }

    fn connect(
        &mut self,
        initial: bool,
        ui: &mut ConnectionUI,
        no_auto_start: bool,
    ) -> anyhow::Result<()> {
        match self.config.clone() {
            ClientDomainConfig::Unix(unix_dom) => {
                self.unix_connect(unix_dom, initial, ui, no_auto_start)
            }
            ClientDomainConfig::Tls(tls) => self.tls_connect(tls, initial, ui),
            ClientDomainConfig::Ssh(ssh) => self.ssh_connect(ssh, initial, ui),
        }
    }

    /// Resolve the path to wezterm for the remote system.
    /// We can't simply derive this from the current executable because
    /// we are being asked to produce a path for the remote system and
    /// we don't really know anything about it.
    /// `path` comes from the SshDoman::remote_wezterm_path option; if set
    /// then the user has told us where to look.
    /// Otherwise, we have to rely on the `PATH` environment for the remote
    /// system, and we don't know if it is even running unix, or whether
    /// any given shell syntax will help us provide a more meaningful
    /// message to the user.
    fn wezterm_bin_path(path: &Option<String>) -> String {
        path.as_deref().unwrap_or("wezterm").to_string()
    }

    fn ssh_connect(
        &mut self,
        ssh_dom: SshDomain,
        initial: bool,
        ui: &mut ConnectionUI,
    ) -> anyhow::Result<()> {
        let ssh_config = mux::ssh::ssh_domain_to_ssh_config(&ssh_dom)?;

        let sess = ssh_connect_with_ui(ssh_config, ui)?;
        let proxy_bin = Self::wezterm_bin_path(&ssh_dom.remote_wezterm_path);

        let cmd = if let Some(cmd) = ssh_dom.override_proxy_command.clone() {
            cmd
        } else if initial {
            format!("{} cli --prefer-mux proxy", proxy_bin)
        } else {
            format!("{} cli --prefer-mux --no-auto-start proxy", proxy_bin)
        };
        ui.output_str(&format!("Running: {}\n", cmd));
        log::debug!("going to run {}", cmd);

        let exec = smol::block_on(sess.exec(&cmd, None))?;

        let mut stderr = exec.stderr;
        std::thread::spawn(move || {
            let mut buf = [0u8; 1024];
            while let Ok(len) = stderr.read(&mut buf) {
                if len == 0 {
                    break;
                } else {
                    let stderr = &buf[0..len];
                    log::error!("ssh stderr: {}", String::from_utf8_lossy(stderr));
                }
            }
        });

        // This is a bit gross, but it helps to surface errors in running
        // the proxy, and prevents us from hanging forever after the process
        // has died
        let mut child = exec.child;
        std::thread::spawn(move || match child.wait() {
            Err(err) => log::error!("waiting on {} failed: {:#}", cmd, err),
            Ok(status) if !status.success() => log::error!("{}: {}", cmd, status),
            _ => {}
        });

        let stream: Box<dyn AsyncReadAndWrite> = Box::new(Async::new(SshStream {
            stdin: exec.stdin,
            stdout: exec.stdout,
        })?);
        self.stream.replace(stream);
        Ok(())
    }

    fn unix_connect(
        &mut self,
        unix_dom: UnixDomain,
        initial: bool,
        ui: &mut ConnectionUI,
        no_auto_start: bool,
    ) -> anyhow::Result<()> {
        let target = unix_dom.target();
        ui.output_str(&format!("Connect to {:?}\n", target));
        log::trace!("connect to {:?}", target);

        let max_attempts = if no_auto_start { Some(1) } else { None };

        let stream = match unix_connect_with_retry(&target, false, max_attempts) {
            Ok(stream) => stream,
            Err(e) => {
                if no_auto_start || unix_dom.no_serve_automatically || !initial {
                    bail!("failed to connect to {:?}: {}", target, e);
                }
                log::warn!(
                    "While connecting to {:?}: {}.  Will try spawning the server.",
                    target,
                    e
                );
                ui.output_str(&format!("Error: {}.  Will try spawning server.\n", e));

                let argv = unix_dom.serve_command()?;

                let mut cmd = std::process::Command::new(&argv[0]);
                cmd.args(&argv[1..]);

                #[cfg(unix)]
                if let Some(mask) = umask::UmaskSaver::saved_umask() {
                    unsafe {
                        cmd.pre_exec(move || {
                            libc::umask(mask);
                            Ok(())
                        });
                    }
                }

                log::warn!("Running: {:?}", cmd);
                ui.output_str(&format!("Running: {:?}\n", cmd));

                let child = cmd
                    .spawn()
                    .with_context(|| format!("while spawning {:?}", cmd))?;
                std::thread::spawn(move || match child.wait_with_output() {
                    Ok(out) => {
                        if let Ok(stdout) = std::str::from_utf8(&out.stdout) {
                            if !stdout.is_empty() {
                                log::warn!("stdout: {}", stdout);
                            }
                        }
                        if let Ok(stderr) = std::str::from_utf8(&out.stderr) {
                            if !stderr.is_empty() {
                                log::warn!("stderr: {}", stderr);
                            }
                        }
                    }
                    Err(err) => {
                        log::error!("spawn: {:#}", err);
                    }
                });

                unix_connect_with_retry(&target, true, None).with_context(|| {
                    format!("(after spawning server) failed to connect to {:?}", target)
                })?
            }
        };

        ui.output_str("Connected!\n");
        stream.set_read_timeout(Some(unix_dom.read_timeout))?;
        stream.set_write_timeout(Some(unix_dom.write_timeout))?;
        let stream: Box<dyn AsyncReadAndWrite> = Box::new(Async::new(stream)?);
        self.stream.replace(stream);
        Ok(())
    }

    pub fn tls_connect(
        &mut self,
        tls_client: TlsDomainClient,
        _initial: bool,
        ui: &mut ConnectionUI,
    ) -> anyhow::Result<()> {
        openssl::init();

        let remote_address = &tls_client.remote_address;

        let remote_host_name = remote_address.split(':').next().ok_or_else(|| {
            anyhow!(
                "expected mux_server_remote_address to have the form 'host:port', but have {}",
                remote_address
            )
        })?;

        // If we are reconnecting and already bootstrapped via SSH, let's see if
        // we can connect using those same credentials and avoid running through
        // the SSH authentication flow.
        if let Some(Ok(_)) = tls_client.ssh_parameters() {
            match self.try_connect(&tls_client, ui, &remote_address, remote_host_name) {
                Ok(stream) => {
                    self.stream.replace(stream);
                    return Ok(());
                }
                Err(err) => {
                    if let Some(ioerr) = err.root_cause().downcast_ref::<std::io::Error>() {
                        match ioerr.kind() {
                            std::io::ErrorKind::ConnectionRefused => {
                                // Server isn't up yet; let's proceed with bootstrap
                            }
                            // Termob fork: NO CACHED CREDENTIALS — the whole
                            // reason to bootstrap.
                            //
                            // This arm exists because of an interaction between
                            // two pieces of code that each look correct alone.
                            // Upstream, `try_connect` loaded the certificate with
                            // `set_certificate_file`, which reports a missing file
                            // as an `openssl::error::ErrorStack`. That does not
                            // downcast to `io::Error`, so this whole `if let` was
                            // skipped and control fell through to the bootstrap
                            // block below — which is how a first-ever connection
                            // was ever able to fetch its credentials.
                            //
                            // The fork later swapped those loads for
                            // `std::fs::read` + `X509::from_pem` (the Android
                            // `openssl no-stdio` fix: `BIO_new_file` does not
                            // exist there, so the `*_file` helpers can never
                            // succeed). That change was described as portability
                            // only, and it is — for the OpenSSL calls. But it also
                            // changed the ERROR TYPE to `io::Error`, and the guard
                            // above branches on exactly that, so a missing cert
                            // started matching the `_` arm and returning early.
                            // Net effect: `bootstrap_via_ssh` could never run on a
                            // device that had not already bootstrapped, i.e. it
                            // only worked where it was not needed.
                            //
                            // `NotFound` means the local credential file is not
                            // there; it says nothing about the remote host, so
                            // bootstrapping is precisely the right next step.
                            std::io::ErrorKind::NotFound => {}
                            _ => {
                                // If it is an IO error that implies that we had an issue
                                // reaching or otherwise talking to the remote host.
                                // Re-attempting the SSH bootstrap most likely will not
                                // succeed so we let this bubble up.
                                return Err(err);
                            }
                        }
                    }
                    ui.output_str(&format!(
                        "Failed to reuse creds: {:?}\nWill retry bootstrap via SSH\n",
                        err
                    ));
                }
            }
        }

        if let Some(Ok(ssh_params)) = tls_client.ssh_parameters() {
            if self.tls_creds.is_none() {
                // We need to bootstrap via an ssh session

                let mut ssh_config = wezterm_ssh::Config::new();
                ssh_config.add_default_config_files();

                let ssh_config =
                    bootstrap_ssh_config(&ssh_config, &ssh_params, &tls_client.ssh_option)?;

                let sess = ssh_connect_with_ui(ssh_config, ui)?;

                let creds = ui.run_and_log_error(|| {
                    // The `tlscreds` command will start the server if needed and then
                    // obtain client credentials that we can use for tls.
                    let cmd = format!(
                        "{} cli tlscreds",
                        Self::wezterm_bin_path(&tls_client.remote_wezterm_path)
                    );

                    ui.output_str(&format!("Running: {}\n", cmd));
                    let mut exec = smol::block_on(sess.exec(&cmd, None))
                        .with_context(|| format!("executing `{}` on remote host", cmd))?;

                    log::debug!("waiting for command to finish");
                    let status = exec.child.wait()?;
                    if !status.success() {
                        anyhow::bail!("{} failed", cmd);
                    }

                    drop(exec.stdin);

                    let mut stderr = exec.stderr;
                    thread::spawn(move || {
                        // stderr is ideally empty
                        let mut err = String::new();
                        let _ = stderr.read_to_string(&mut err);
                        if !err.is_empty() {
                            log::error!("remote: `{}` stderr -> `{}`", cmd, err);
                        }
                    });

                    let creds = match Pdu::decode(exec.stdout)
                        .context("reading tlscreds response")?
                        .pdu
                    {
                        Pdu::GetTlsCredsResponse(creds) => creds,
                        _ => bail!("unexpected response to tlscreds"),
                    };

                    // Save the credentials to disk, as that is currently the easiest
                    // way to get them into openssl.  Ideally we'd keep these entirely
                    // in memory.
                    // The CA is public information; the client credential is
                    // NOT — `client_cert_pem` carries the private key in the
                    // same file. Termob fork: this used to go through a plain
                    // `std::fs::write`, which leaves the mode to the umask and
                    // on a typical desktop produces a world-readable 0644 key.
                    // The server writes the very same bytes owner-only (see
                    // `wezterm-mux-server-impl::pki::write_atomic`), so this was
                    // the one place where bootstrapping quietly downgraded the
                    // secret it had just fetched — and it is now the default
                    // path for termob's TLS picker.
                    //
                    // Both go through the same writer even though only one is
                    // secret: the CA is read by the very same connect path, so
                    // leaving it on a non-atomic `std::fs::write` would keep a
                    // window where a concurrent connect reads a truncated
                    // ca.pem and fails to parse it. Same failure, same fix —
                    // only the permission bit differs.
                    write_pem_atomic(
                        &self.tls_creds_ca_path()?,
                        creds.ca_cert_pem.as_bytes(),
                        false,
                    )?;
                    write_pem_atomic(
                        &self.tls_creds_cert_path()?,
                        creds.client_cert_pem.as_bytes(),
                        true,
                    )?;
                    log::info!("got TLS creds");
                    Ok(creds)
                })?;
                self.tls_creds.replace(creds);
            }
        }

        let cloned_ui = ui.clone();
        let stream = cloned_ui.run_and_log_error({
            || self.try_connect(&tls_client, ui, &remote_address, remote_host_name)
        })?;
        self.stream.replace(stream);
        Ok(())
    }

    fn try_connect(
        &mut self,
        tls_client: &TlsDomainClient,
        ui: &mut ConnectionUI,
        remote_address: &str,
        remote_host_name: &str,
    ) -> anyhow::Result<Box<dyn AsyncReadAndWrite>> {
        let mut connector = SslConnector::builder(SslMethod::tls())?;

        // Credentials are read into memory by us and handed to OpenSSL as
        // in-memory objects, rather than using the `*_file` helpers.
        //
        // The `*_file` helpers go through `BIO_new_file`, which does not exist
        // when OpenSSL is built with `no-stdio`. The `openssl-src` crate passes
        // `no-stdio` for every Android target, so on Android
        // `SSL_CTX_use_certificate_file` can never succeed: it fails with
        // `BIO_new_ex:init fail` even when the file exists and is readable.
        // Reading the bytes ourselves and parsing them with the memory-BIO
        // based `X509::from_pem` / `X509::stack_from_pem` /
        // `PKey::private_key_from_pem` works on every platform (see `load_cert`
        // below, which already took this route).
        //
        // This is a portability fix only: all three conversions below
        // (`set_certificate_file`, `set_certificate_chain_file`,
        // `set_private_key_file`) keep their original semantics, including the
        // fact that a `pem_ca` chain overrides the leaf set from `pem_cert`.
        let cert_file = match tls_client.pem_cert.clone() {
            Some(cert) => cert,
            None => self.tls_creds_cert_path()?,
        };

        let cert = load_cert(&cert_file).context(format!(
            "loading certificate {} for TLS client",
            cert_file.display()
        ))?;
        connector.set_certificate(&cert).context(format!(
            "set_certificate from {} for TLS client",
            cert_file.display()
        ))?;

        if let Some(chain_file) = tls_client.pem_ca.as_ref() {
            // In-memory equivalent of `set_certificate_chain_file`, with the
            // same semantics: the file's first certificate becomes the leaf
            // (overriding the one set just above, exactly as the OpenSSL API
            // does) and the remaining ones are sent as the chain.
            let chain_bytes = std::fs::read(chain_file).context(format!(
                "reading certificate chain {} for TLS client",
                chain_file.display()
            ))?;
            let mut chain = X509::stack_from_pem(&chain_bytes)
                .context(format!(
                    "parsing certificate chain {} for TLS client",
                    chain_file.display()
                ))?
                .into_iter();
            let Some(leaf) = chain.next() else {
                bail!(
                    "certificate chain {} contains no certificates",
                    chain_file.display()
                );
            };
            connector.set_certificate(&leaf).context(format!(
                "set_certificate from chain {} for TLS client",
                chain_file.display()
            ))?;
            for extra in chain {
                connector.add_extra_chain_cert(extra).context(format!(
                    "add_extra_chain_cert from {} for TLS client",
                    chain_file.display()
                ))?;
            }
        }

        let key_file = match tls_client.pem_private_key.clone() {
            Some(key) => key,
            None => self.tls_creds_cert_path()?,
        };
        let key_bytes = std::fs::read(&key_file).context(format!(
            "reading private key {} for TLS client",
            key_file.display()
        ))?;
        let key = PKey::private_key_from_pem(&key_bytes).context(format!(
            "parsing private key {} for TLS client",
            key_file.display()
        ))?;
        connector.set_private_key(&key).context(format!(
            "set_private_key from {} for TLS client",
            key_file.display()
        ))?;

        fn load_cert(name: &Path) -> anyhow::Result<X509> {
            let cert_bytes = std::fs::read(name)?;
            log::trace!("loaded {}", name.display());
            Ok(X509::from_pem(&cert_bytes)?)
        }
        for name in &tls_client.pem_root_certs {
            if name.is_dir() {
                for entry in std::fs::read_dir(name)? {
                    if let Ok(cert) = load_cert(&entry?.path()) {
                        connector.cert_store_mut().add_cert(cert).ok();
                    }
                }
            } else {
                connector.cert_store_mut().add_cert(load_cert(name)?)?;
            }
        }

        if let Ok(ca_path) = self.tls_creds_ca_path() {
            if ca_path.exists() {
                connector.cert_store_mut().add_cert(load_cert(&ca_path)?)?;
            }
        }

        let connector = connector.build();
        let connector = connector
            .configure()?
            .verify_hostname(!tls_client.accept_invalid_hostnames);

        ui.output_str(&format!("Connecting to {} using TLS\n", remote_address));
        let stream = tcp_connect_within(remote_address, tls_client.connect_timeout)
            .with_context(|| format!("connecting to {}", remote_address))?;
        stream.set_nodelay(true)?;
        stream.set_write_timeout(Some(tls_client.write_timeout))?;
        stream.set_read_timeout(Some(tls_client.read_timeout))?;

        let stream = Box::new(Async::new(AsyncSslStream::new(
            connector
                .connect(
                    tls_client
                        .expected_cn
                        .as_deref()
                        .unwrap_or(remote_host_name),
                    stream,
                )
                .with_context(|| {
                    format!(
                        "SslConnector for {} with host name {}",
                        remote_address, remote_host_name,
                    )
                })?,
        ))?);
        ui.output_str("TLS Connected!\n");
        Ok(stream)
    }
}

/// Turn a domain name into something usable as a single directory name on
/// every platform we ship.
///
/// Termob fork. The bootstrapped credentials live in a directory named after
/// the domain, and termob derives that name from the connection target — a TLS
/// domain is `tls:<host>:<port>` — so that two servers cannot share one
/// credential slot. On Windows `:` is not a legal filename character (and
/// `name:stream` addresses an alternate data stream instead), so
/// `create_dir_all` failed and TLS bootstrap could not work there at all.
///
/// The mapping is a percent-encoding rather than a "replace bad characters
/// with `_`" pass, because the latter is not injective: `host:8443` and
/// `host_8443` would collapse onto the same directory, and the whole reason
/// the name carries the target is to keep two servers apart. `%` itself is
/// escaped, so the encoding stays reversible and can never produce a
/// collision. It is also fixed rather than hashed: a hash would move every
/// stored credential whenever the hasher changed, forcing a silent
/// re-bootstrap.
///
/// Applied on every platform, not behind `cfg(windows)`: one code path that
/// the unix tests actually exercise beats a Windows-only branch that only
/// breaks on the machine nobody is testing on.
fn escape_for_directory_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        // Deliberately a small allowlist: anything outside it is escaped,
        // which covers `:` `\` `/` `|` `<` `>` `"` `?` `*` and control
        // characters without having to enumerate each platform's rules.
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
            out.push(c);
        } else {
            for byte in c.to_string().as_bytes() {
                out.push_str(&format!("%{byte:02X}"));
            }
        }
    }
    out
}

/// Build the `ConfigMap` for the one-shot bootstrap ssh session.
///
/// Termob fork. The layering mirrors `mux::ssh::ssh_domain_to_ssh_config`:
/// per-host defaults from `for_host`, then the caller's `ssh_option`, then
/// the `user`/`port` parsed out of `bootstrap_via_ssh`. The bootstrap target
/// is the more specific statement of intent, so it stays last and wins over a
/// `user`/`port` that happened to arrive through `ssh_option`.
///
/// Extracted from `tls_connect` rather than left inline so that the ordering
/// above is testable: with an empty `ssh_option` the result has to match what
/// `tls_connect` produced before this option existed, and that is the property
/// most likely to be broken by a later edit.
fn bootstrap_ssh_config(
    ssh_config: &wezterm_ssh::Config,
    ssh_params: &config::SshParameters,
    ssh_option: &HashMap<String, String>,
) -> anyhow::Result<wezterm_ssh::ConfigMap> {
    let mut fields = ssh_params.host_and_port.split(':');
    let host = fields
        .next()
        .ok_or_else(|| anyhow::anyhow!("no host component somehow"))?;
    let port = fields.next();

    let mut ssh_config = ssh_config.for_host(host);
    for (k, v) in ssh_option {
        ssh_config.insert(k.to_string(), v.to_string());
    }
    if let Some(username) = &ssh_params.username {
        ssh_config.insert("user".to_string(), username.to_string());
    }
    if let Some(port) = port {
        ssh_config.insert("port".to_string(), port.to_string());
    }
    Ok(ssh_config)
}

/// Write a bootstrapped PEM file, replacing any previous one atomically.
///
/// `owner_only` restricts the result to its owner on unix; pass it for
/// anything carrying a private key.
///
/// Termob fork. Created because the bootstrap path stored a freshly fetched
/// client credential — cert AND private key in one file — with `std::fs::write`,
/// which leaves the mode to the umask and on a typical desktop produces a
/// world-readable 0644 key.
///
/// The write goes through a sibling temporary file and a rename, so a reader
/// only ever sees the whole old file or the whole new one. That matters here:
/// termob supports several windows against one server, and two of them
/// bootstrapping the same domain at the same moment would otherwise let one
/// read a half-written credential and fail with a PEM parse error that says
/// nothing about the real cause. The atomicity is not unix-specific, so it is
/// NOT behind a `cfg` — only the permission bits are, since that is the one
/// part with no Windows equivalent (there the file inherits the ACL of the
/// per-user profile directory it is created in).
///
/// The temporary file is also what makes the permission guarantee hold on a
/// rewrite: `mode` applies only when a file is CREATED, so writing in place
/// over a credential left behind by an older build would silently keep its
/// 0644.
///
/// The temporary name carries the process id, so two processes bootstrapping
/// the same domain at once cannot collide on it. With a shared name one of
/// them would unlink the other's file mid-write and its rename would then fail
/// with a bare `No such file or directory` — a nondeterministic error pointing
/// nowhere near the cause.
fn write_pem_atomic(path: &Path, bytes: &[u8], owner_only: bool) -> anyhow::Result<()> {
    use std::io::Write as _;

    // Same directory: `rename` is only atomic within one filesystem.
    let mut tmp_path = path.as_os_str().to_os_string();
    tmp_path.push(format!(".tmp.{}", std::process::id()));
    let tmp_path = PathBuf::from(tmp_path);

    // A leftover from an interrupted run of THIS pid (recycled after a crash)
    // would fail `create_new` below, and on unix could carry an older mode.
    match std::fs::remove_file(&tmp_path) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(anyhow::Error::new(err))
                .with_context(|| format!("replacing {}", tmp_path.display()))
        }
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if owner_only {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(&tmp_path)
        .with_context(|| format!("creating {}", tmp_path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", tmp_path.display()))?;
    // Flush to disk before publishing the name: a crash between the two would
    // otherwise leave a correctly named but empty credential.
    file.sync_all()
        .with_context(|| format!("syncing {}", tmp_path.display()))?;
    drop(file);

    // `fs::rename` replaces an existing destination on both unix and Windows
    // (the latter via `MOVEFILE_REPLACE_EXISTING`).
    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} to {}", tmp_path.display(), path.display()))
}

/// How long a single address may take, given the time `left` in the overall
/// budget and how many addresses (including this one) are still to be tried.
///
/// Split out from [`tcp_connect_within`] because the edges are what bite:
/// dividing by zero, and handing `TcpStream::connect_timeout` a zero
/// `Duration`, which it rejects outright — so an over-thin slice would turn
/// "keep trying" into an instant hard failure. Both are pinned by tests; the
/// surrounding connect loop is not reproducible without a firewall that drops
/// SYNs.
///
/// `Duration` division takes a `u32`, so the address count is clamped into
/// range; a resolver never returns anywhere near that many, and clamping keeps
/// the conversion total instead of relying on a cast that could wrap.
fn connect_budget_slice(left: Duration, remaining_addrs: usize) -> Duration {
    let divisor = remaining_addrs.clamp(1, u32::MAX as usize) as u32;
    (left / divisor).max(Duration::from_millis(1))
}

/// Connect to `remote_address` (`host:port`), giving up after `budget`.
///
/// Termob fork. `TcpStream::connect` carries no timeout: against a peer that
/// silently drops SYNs — a firewall, a stale LAN address, a phone that has
/// roamed off the network — it blocks for the OS retry budget (~75s on macOS,
/// ~130s on Linux). That is indistinguishable from a hung app, and it is the
/// most common connection failure on mobile.
///
/// A name can resolve to several addresses (typically one A and one AAAA).
/// Each gets a slice of the remaining budget rather than a fresh copy of it,
/// so the CONNECT phase is bounded by `budget` no matter how many addresses
/// DNS returns; a blackholed AAAA can no longer consume the entire wait and
/// leave a perfectly reachable A record untried. The last connect error is
/// propagated — a refusal reports as a refusal, not as a timeout — and only a
/// budget that expired before any address was tried reports as a timeout.
///
/// **Name resolution is NOT covered by the budget.** `to_socket_addrs` calls
/// `getaddrinfo`, which has no portable timeout; bounding it means resolving on
/// a throwaway thread and abandoning it, which leaks a thread per attempt. The
/// resolver has its own (OS/libc-configured) timeout, so this is bounded, just
/// not by us — an unreachable DNS server can still delay a connect beyond
/// `budget`. Callers wanting a hard ceiling must impose it above this function.
/// The common mobile failure this exists for — a reachable network with a
/// silently dropped SYN — resolves promptly and is fully covered.
fn tcp_connect_within(remote_address: &str, budget: Duration) -> anyhow::Result<TcpStream> {
    let addrs: Vec<_> = remote_address
        .to_socket_addrs()
        .with_context(|| format!("resolving {}", remote_address))?
        .collect();
    if addrs.is_empty() {
        bail!("{} resolved to no addresses", remote_address);
    }

    let started = std::time::Instant::now();
    let mut remaining_addrs = addrs.len();
    let mut last_err = None;

    for addr in addrs {
        let left = budget.saturating_sub(started.elapsed());
        if left.is_zero() {
            break;
        }
        let slice = connect_budget_slice(left, remaining_addrs);
        remaining_addrs = remaining_addrs.saturating_sub(1);
        match TcpStream::connect_timeout(&addr, slice) {
            Ok(stream) => return Ok(stream),
            Err(err) => {
                log::debug!("connect to {addr} failed: {err:#}");
                last_err = Some(err);
            }
        }
    }

    match last_err {
        Some(err) => Err(anyhow::Error::new(err)),
        // Every address was skipped because the budget ran out before its turn.
        None => bail!(
            "timed out after {:?} connecting to {}",
            budget,
            remote_address
        ),
    }
}

impl Client {
    fn new(local_domain_id: Option<DomainId>, mut reconnectable: Reconnectable) -> Self {
        let client_domain_config = reconnectable.config.clone();
        let is_reconnectable = reconnectable.reconnectable();
        let is_local = reconnectable.is_local();
        let (sender, mut receiver) = unbounded();
        let client_id = ClientId::new();
        // Termob fork: see `Client::connection_live`.
        let connection_live = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true));
        let thread_connection_live = std::sync::Arc::clone(&connection_live);

        thread::spawn(move || {
            use std::sync::atomic::Ordering;
            const BASE_INTERVAL: Duration = Duration::from_secs(1);
            const MAX_INTERVAL: Duration = Duration::from_secs(10);

            let mut backoff = BASE_INTERVAL;
            'client_thread: loop {
                if let Err(e) = client_thread(&mut reconnectable, local_domain_id, &mut receiver) {
                    // Termob fork: the transport is down from here on. Flag it
                    // before any of the give-up branches below so a frontend
                    // never sees a live flag on a dead connection.
                    thread_connection_live.store(false, Ordering::Relaxed);
                    if !reconnectable.reconnectable() || local_domain_id.is_none() {
                        log::debug!("client thread ended: {}", e);
                        break;
                    }

                    let local_domain_id = local_domain_id.expect("checked above");

                    if let Some(ioerr) = e.root_cause().downcast_ref::<std::io::Error>() {
                        if let std::io::ErrorKind::UnexpectedEof = ioerr.kind() {
                            // Termob fork: upstream treated a plain EOF as a
                            // deliberate server-side close and gave up. On
                            // mobile, the single most common failure mode is a
                            // silent half-close while roaming between networks
                            // (Wi-Fi <-> cellular): the TLS read returns 0,
                            // decoding fails with UnexpectedEof, and upstream
                            // would never reconnect even for a reconnectable
                            // domain. Reconnect instead; a genuinely destroyed
                            // client still stops via NotReconnectableError
                            // below, and a permanently gone server just keeps
                            // the existing capped backoff until the domain is
                            // detached.
                            log::error!(
                                "server closed connection ({}); will attempt to reconnect",
                                e
                            );
                        }
                    }

                    if let Some(err) = e.root_cause().downcast_ref::<NotReconnectableError>() {
                        log::error!("{}; won't try to reconnect", err);
                        break;
                    }

                    let mut ui = ConnectionUI::new();
                    ui.title("wezterm: Reconnecting...");

                    loop {
                        ui.sleep_with_reason(
                            &format!("client disconnected {}; will reconnect", e),
                            backoff,
                        )
                        .ok();

                        // Termob fork: give up once nothing can use this
                        // connection any more. Upstream's retry loop had no
                        // exit other than a successful reconnect, so detaching
                        // a domain (or closing its last pane) left this OS
                        // thread reconnecting to a server nobody was listening
                        // to, forever, at up to one TLS handshake every
                        // MAX_INTERVAL. On mobile that is a background battery
                        // and data drain that outlives the UI that started it.
                        //
                        // The channel is the precise signal: `sender` lives in
                        // `Client`, which lives in the `ClientInner` that
                        // `ClientDomain::perform_detach` drops, so the channel
                        // closes exactly when the last holder is gone. A
                        // network drop does NOT close it — the domain keeps
                        // `inner` across disconnects, which is what makes the
                        // roaming reconnect above work — so this cannot cut a
                        // reconnect that someone is still waiting on.
                        if receiver.is_closed() {
                            log::info!(
                                "nothing is using this connection any more; \
                                 abandoning reconnect attempts"
                            );
                            break 'client_thread;
                        }

                        let initial = false;
                        let no_auto_start = true; // Don't auto-start on a reconnect
                        match reconnectable.connect(initial, &mut ui, no_auto_start) {
                            Ok(_) => {
                                backoff = BASE_INTERVAL;
                                // Termob fork: transport is carrying traffic again.
                                thread_connection_live.store(true, Ordering::Relaxed);
                                log::error!("Reconnected!");
                                promise::spawn::spawn_into_main_thread(async move {
                                    ClientDomain::reattach(local_domain_id, ui).await.ok();
                                })
                                .detach();
                                break;
                            }
                            Err(err) => {
                                backoff = (backoff + backoff).min(MAX_INTERVAL);
                                ui.output_str(&format!(
                                    "problem reconnecting: {}; will reconnect in {:?}\n",
                                    err, backoff
                                ));
                            }
                        }
                    }
                } else {
                    // Termob fork: no error, but the reader loop is over — the
                    // transport is not carrying traffic any more either.
                    thread_connection_live.store(false, Ordering::Relaxed);
                    log::error!("client_thread returned without any error condition");
                    break;
                }
            }

            async fn detach(local_domain_id: DomainId) -> anyhow::Result<()> {
                if let Some(mux) = Mux::try_get() {
                    let client_domain = mux
                        .get_domain(local_domain_id)
                        .ok_or_else(|| anyhow!("no such domain {}", local_domain_id))?;
                    let client_domain =
                        client_domain
                            .downcast_ref::<ClientDomain>()
                            .ok_or_else(|| {
                                anyhow!("domain {} is not a ClientDomain instance", local_domain_id)
                            })?;
                    client_domain.perform_detach();
                }
                Ok(())
            }
            if let Some(domain_id) = local_domain_id {
                promise::spawn::spawn_into_main_thread(async move {
                    detach(domain_id).await.ok();
                })
                .detach();
            }
        });

        Self {
            sender,
            local_domain_id,
            is_reconnectable,
            is_local,
            client_id,
            client_domain_config,
            connection_live,
        }
    }

    /// Termob fork: is the transport currently carrying traffic?
    ///
    /// See [`Client::connection_live`] for why `Domain::state()` cannot be
    /// used for this. A `false` result means the reader thread hit an error;
    /// whether it will come back depends on [`Client::is_reconnectable`]
    /// (reconnectable domains retry with a capped backoff, others stay down).
    pub fn is_connection_live(&self) -> bool {
        self.connection_live
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn into_client_domain_config(self) -> ClientDomainConfig {
        self.client_domain_config
    }

    pub async fn verify_version_compat(
        &self,
        ui: &ConnectionUI,
    ) -> anyhow::Result<GetCodecVersionResponse> {
        match self
            .get_codec_version(GetCodecVersion {})
            .or(async {
                smol::Timer::after(Duration::from_secs(60)).await;
                Err(Timeout).context("Timeout")
            })
            .await
        {
            Ok(info) if info.codec_vers == CODEC_VERSION => {
                log::trace!(
                    "Server version is {} (codec version {})",
                    info.version_string,
                    info.codec_vers
                );
                self.set_client_id(SetClientId {
                    client_id: self.client_id.clone(),
                    is_proxy: false,
                })
                .await?;
                Ok(info)
            }
            Ok(info) => {
                let err = IncompatibleVersionError {
                    version: info.version_string,
                    codec_vers: info.codec_vers,
                };
                ui.output_str(&err.to_string());
                log::error!("{:?}", err);
                return Err(err.into());
            }
            Err(err) => {
                log::trace!("{:?}", err);
                let msg = if err.root_cause().is::<Timeout>() {
                    "Timed out while parsing the response from the server. \
                    This may be due to network connectivity issues"
                        .to_string()
                } else if err.root_cause().is::<CorruptResponse>() {
                    "Received an implausible and likely corrupt response from \
                    the server. This can happen if the remote host outputs \
                    to stdout prior to running commands. \
                    Check your shell startup!"
                        .to_string()
                } else if err.root_cause().is::<ChannelSendError>() {
                    "Internal channel was closed prior to sending request. \
                    This may indicate that the remote host output invalid data \
                    to stdout prior to running the requested command. \
                    Check your shell startup!"
                        .to_string()
                } else {
                    format!(
                        "Please install the same version of wezterm on both \
                     the client and server! \
                     The server reported error '{err}' while being asked for its \
                     version.  This likely means that the server is older \
                     than the client, but it could also happen if the remote \
                     host outputs to stdout prior to running commands. \
                     Check your shell startup!",
                    )
                };
                ui.output_str(&msg);
                bail!("{}", msg);
            }
        }
    }

    #[allow(dead_code)]
    pub fn local_domain_id(&self) -> Option<DomainId> {
        self.local_domain_id
    }

    fn compute_unix_domain(
        prefer_mux: bool,
        class_name: &str,
    ) -> anyhow::Result<config::UnixDomain> {
        match std::env::var_os("WEZTERM_UNIX_SOCKET") {
            Some(path) if !path.is_empty() => Ok(config::UnixDomain {
                socket_path: Some(path.into()),
                ..Default::default()
            }),
            Some(_) | None => {
                if !prefer_mux {
                    if let Ok(gui) = crate::discovery::resolve_gui_sock_path(class_name) {
                        return Ok(config::UnixDomain {
                            socket_path: Some(gui),
                            no_serve_automatically: true,
                            ..Default::default()
                        });
                    }
                }

                let config = configuration();
                Ok(config
                    .unix_domains
                    .first()
                    .ok_or_else(|| {
                        anyhow!(
                            "no default unix domain is configured and WEZTERM_UNIX_SOCKET \
                             is not set in the environment"
                        )
                    })?
                    .clone())
            }
        }
    }

    pub fn new_default_unix_domain(
        initial: bool,
        ui: &mut ConnectionUI,
        no_auto_start: bool,
        prefer_mux: bool,
        class_name: &str,
    ) -> anyhow::Result<Self> {
        let unix_dom = Self::compute_unix_domain(prefer_mux, class_name)?;
        Self::new_unix_domain(None, &unix_dom, initial, ui, no_auto_start)
    }

    pub fn new_unix_domain(
        local_domain_id: Option<DomainId>,
        unix_dom: &UnixDomain,
        initial: bool,
        ui: &mut ConnectionUI,
        no_auto_start: bool,
    ) -> anyhow::Result<Self> {
        let mut reconnectable =
            Reconnectable::new(ClientDomainConfig::Unix(unix_dom.clone()), None);
        reconnectable.connect(initial, ui, no_auto_start)?;
        Ok(Self::new(local_domain_id, reconnectable))
    }

    pub fn new_tls(
        local_domain_id: DomainId,
        tls_client: &TlsDomainClient,
        ui: &mut ConnectionUI,
    ) -> anyhow::Result<Self> {
        let mut reconnectable =
            Reconnectable::new(ClientDomainConfig::Tls(tls_client.clone()), None);
        let no_auto_start = true;
        reconnectable.connect(true, ui, no_auto_start)?;
        Ok(Self::new(Some(local_domain_id), reconnectable))
    }

    pub fn new_ssh(
        local_domain_id: DomainId,
        ssh_dom: &SshDomain,
        ui: &mut ConnectionUI,
    ) -> anyhow::Result<Self> {
        let mut reconnectable = Reconnectable::new(ClientDomainConfig::Ssh(ssh_dom.clone()), None);
        let no_auto_start = true;
        reconnectable.connect(true, ui, no_auto_start)?;
        Ok(Self::new(Some(local_domain_id), reconnectable))
    }

    pub async fn send_pdu(&self, pdu: Pdu) -> anyhow::Result<Pdu> {
        let (promise, rx) = bounded(1);
        self.sender
            .send(ReaderMessage::SendPdu { pdu, promise })
            .await
            .map_err(|_| ChannelSendError)
            .context("send_pdu send")?;
        rx.recv().await.context("send_pdu recv")?
    }

    pub async fn resolve_pane_id(&self, pane_id: Option<PaneId>) -> anyhow::Result<PaneId> {
        let pane_id: PaneId = match pane_id {
            Some(p) => p,
            None => {
                if let Ok(pane) = std::env::var("WEZTERM_PANE") {
                    pane.parse()?
                } else {
                    let mut clients = self.list_clients().await?.clients;
                    clients.retain(|client| client.focused_pane_id.is_some());
                    clients.sort_by(|a, b| b.last_input.cmp(&a.last_input));
                    if clients.is_empty() {
                        anyhow::bail!(
                            "--pane-id was not specified and $WEZTERM_PANE
                         is not set in the environment, and I couldn't
                         determine which pane was currently focused"
                        );
                    }

                    clients[0]
                        .focused_pane_id
                        .expect("to have filtered out above")
                }
            }
        };
        Ok(pane_id)
    }

    rpc!(ping, Ping = (), Pong);
    rpc!(list_panes, ListPanes = (), ListPanesResponse);
    rpc!(spawn_v2, SpawnV2, SpawnResponse);
    rpc!(split_pane, SplitPane, SpawnResponse);
    rpc!(
        move_pane_to_new_tab,
        MovePaneToNewTab,
        MovePaneToNewTabResponse
    );
    rpc!(write_to_pane, WriteToPane, UnitResponse);
    rpc!(send_paste, SendPaste, UnitResponse);
    rpc!(key_down, SendKeyDown, UnitResponse);
    rpc!(mouse_event, SendMouseEvent, UnitResponse);
    rpc!(resize, Resize, UnitResponse);
    rpc!(set_zoomed, SetPaneZoomed, UnitResponse);
    rpc!(activate_pane_direction, ActivatePaneDirection, UnitResponse);
    rpc!(
        get_pane_render_changes,
        GetPaneRenderChanges,
        LivenessResponse
    );
    rpc!(get_lines, GetLines, GetLinesResponse);
    rpc!(
        get_dimensions,
        GetPaneRenderableDimensions,
        GetPaneRenderableDimensionsResponse
    );
    rpc!(get_codec_version, GetCodecVersion, GetCodecVersionResponse);
    rpc!(get_tls_creds, GetTlsCreds = (), GetTlsCredsResponse);
    rpc!(
        search_scrollback,
        SearchScrollbackRequest,
        SearchScrollbackResponse
    );
    rpc!(kill_pane, KillPane, UnitResponse);
    rpc!(set_client_id, SetClientId, UnitResponse);
    rpc!(list_clients, GetClientList = (), GetClientListResponse);
    rpc!(set_window_workspace, SetWindowWorkspace, UnitResponse);
    rpc!(set_focused_pane_id, SetFocusedPane, UnitResponse);
    rpc!(get_image_cell, GetImageCell, GetImageCellResponse);
    rpc!(set_configured_palette_for_pane, SetPalette, UnitResponse);
    rpc!(set_tab_title, TabTitleChanged, UnitResponse);
    rpc!(set_window_title, WindowTitleChanged, UnitResponse);
    rpc!(rename_workspace, RenameWorkspace, UnitResponse);
    rpc!(erase_scrollback, EraseScrollbackRequest, UnitResponse);
    rpc!(
        get_pane_direction,
        GetPaneDirection,
        GetPaneDirectionResponse
    );
    rpc!(adjust_pane_size, AdjustPaneSize, UnitResponse);
}

/// Termob fork tests: the bounded TCP connect added alongside
/// `TlsDomainClient::connect_timeout`, plus the on-disk handling of
/// bootstrapped TLS credentials (directory naming and atomic writes).
#[cfg(test)]
mod termob_fork_tests {
    use super::{
        bootstrap_ssh_config, connect_budget_slice, escape_for_directory_name, tcp_connect_within,
    };
    use std::collections::HashMap;
    use std::time::Duration;

    /// A `Config` that resolves `$HOME` (and every other env lookup) from a
    /// fixed map instead of the machine running the test, and that parses no
    /// `ssh_config` files. Without this the expectations below would depend on
    /// whoever's home directory the test happens to run in.
    fn hermetic_config() -> wezterm_ssh::Config {
        let mut env = wezterm_ssh::ConfigMap::new();
        env.insert("HOME".to_string(), "/home/tester".to_string());
        let mut config = wezterm_ssh::Config::new();
        config.assign_environment(env);
        config
    }

    fn params(user: Option<&str>, host_and_port: &str) -> config::SshParameters {
        config::SshParameters {
            username: user.map(str::to_string),
            host_and_port: host_and_port.to_string(),
        }
    }

    /// The guard for the whole `ssh_option` addition: with the option empty —
    /// which is every configuration that existed before it — the bootstrap
    /// session must be configured exactly as it was when the code was inline.
    /// `identityfile` here is the `$HOME` default, i.e. nothing the caller
    /// injected.
    #[test]
    fn empty_ssh_option_leaves_the_bootstrap_config_unchanged() {
        let config = hermetic_config();
        let built = bootstrap_ssh_config(
            &config,
            &params(Some("alice"), "example.com:2222"),
            &HashMap::new(),
        )
        .unwrap();

        let mut expected = config.for_host("example.com");
        expected.insert("user".to_string(), "alice".to_string());
        expected.insert("port".to_string(), "2222".to_string());

        assert_eq!(built, expected);
        assert_eq!(
            built.get("identityfile").map(String::as_str),
            Some(
                "/home/tester/.ssh/id_dsa /home/tester/.ssh/id_ecdsa \
                 /home/tester/.ssh/id_ed25519 /home/tester/.ssh/id_rsa"
            )
        );
    }

    /// The reason the option exists: on a phone there is no `~/.ssh` and no
    /// agent, so the identity can only come from the caller. It has to replace
    /// the `$HOME` default rather than be appended after it — an unreadable
    /// default path ahead of it is what libssh would try first.
    #[test]
    fn caller_identity_file_overrides_the_home_default() {
        let mut ssh_option = HashMap::new();
        ssh_option.insert(
            "identityfile".to_string(),
            "/data/app/keys/id_ed25519".to_string(),
        );
        ssh_option.insert("identitiesonly".to_string(), "yes".to_string());

        let built = bootstrap_ssh_config(
            &hermetic_config(),
            &params(Some("alice"), "example.com"),
            &ssh_option,
        )
        .unwrap();

        assert_eq!(
            built.get("identityfile").map(String::as_str),
            Some("/data/app/keys/id_ed25519")
        );
        assert_eq!(built.get("identitiesonly").map(String::as_str), Some("yes"));
    }

    /// Ordering, mirroring `mux::ssh::ssh_domain_to_ssh_config`: whatever the
    /// caller passed, the target the user actually typed into
    /// `bootstrap_via_ssh` decides who we log in as and on which port.
    /// Otherwise a stale `user` left in `ssh_option` would silently redirect
    /// the login.
    #[test]
    fn bootstrap_target_user_and_port_win_over_ssh_option() {
        let mut ssh_option = HashMap::new();
        ssh_option.insert("user".to_string(), "someone-else".to_string());
        ssh_option.insert("port".to_string(), "9999".to_string());

        let built = bootstrap_ssh_config(
            &hermetic_config(),
            &params(Some("alice"), "example.com:2222"),
            &ssh_option,
        )
        .unwrap();

        assert_eq!(built.get("user").map(String::as_str), Some("alice"));
        assert_eq!(built.get("port").map(String::as_str), Some("2222"));
    }

    /// A target without a user is valid (`host` alone); the local user default
    /// from `for_host` must survive, and `ssh_option` must still be able to set
    /// it — this is the one case where the caller's `user` is not overridden.
    #[test]
    fn ssh_option_user_applies_when_the_target_has_none() {
        let mut ssh_option = HashMap::new();
        ssh_option.insert("user".to_string(), "someone-else".to_string());

        let built = bootstrap_ssh_config(
            &hermetic_config(),
            &params(None, "example.com"),
            &ssh_option,
        )
        .unwrap();

        assert_eq!(built.get("user").map(String::as_str), Some("someone-else"));
        assert_eq!(built.get("port").map(String::as_str), Some("22"));
    }

    /// The canonical TLS domain name carries the target, so it always contains
    /// colons — which Windows rejects outright as a filename character. Before
    /// this, `create_dir_all` failed there and TLS bootstrap was impossible.
    #[test]
    fn domain_name_becomes_a_legal_directory_name() {
        let escaped = escape_for_directory_name("tls:10.0.0.5:8080");
        assert_eq!(escaped, "tls%3A10.0.0.5%3A8080");
        for illegal in ['<', '>', ':', '"', '/', '\\', '|', '?', '*'] {
            // Edition 2018: inline captures are NOT interpolated in an
            // `assert!` message, so the values are passed as arguments.
            assert!(
                !escaped.contains(illegal),
                "{:?} is not legal in a Windows filename: {}",
                illegal,
                escaped
            );
        }
    }

    /// Escaping must stay injective: the whole point of putting the target in
    /// the name is that two servers get separate credential directories. A
    /// "replace bad characters with `_`" pass would collapse these two.
    #[test]
    fn different_targets_never_share_a_directory() {
        assert_ne!(
            escape_for_directory_name("tls:host:8443"),
            escape_for_directory_name("tls:host_8443")
        );
        // The escape character itself has to be escaped, or a name containing
        // a literal `%3A` would collide with one containing a real colon.
        assert_ne!(
            escape_for_directory_name("tls:a"),
            escape_for_directory_name("tls%3Aa")
        );
    }

    /// Ordinary characters are left alone, so an already-safe name keeps a
    /// readable directory that a user can find by eye.
    #[test]
    fn safe_names_are_unchanged() {
        assert_eq!(escape_for_directory_name("termob-tls"), "termob-tls");
        assert_eq!(
            escape_for_directory_name("host.example_1"),
            "host.example_1"
        );
    }

    /// The credential is written whole or not at all, and when asked for
    /// owner-only it stays 0600 — including when it REPLACES an existing file,
    /// which is where an in-place write would have kept the old mode.
    #[test]
    fn private_pem_is_replaced_atomically_and_stays_owner_only() {
        let dir = std::env::temp_dir().join(format!("termob-pem-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("cert.pem");

        // Pre-existing, deliberately world-readable, with different content.
        std::fs::write(&path, b"stale").expect("seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        }

        super::write_pem_atomic(&path, b"fresh", true).expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"fresh");
        assert!(
            !dir.join(format!("cert.pem.tmp.{}", std::process::id()))
                .exists(),
            "temporary file must not be left behind"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key must not be readable by others");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The CA goes through the same writer with `owner_only = false`: it is
    /// public information, and forcing 0600 on it would be a gratuitous
    /// difference from what the server writes.
    #[test]
    fn public_pem_is_not_restricted() {
        let dir = std::env::temp_dir().join(format!("termob-ca-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("ca.pem");

        super::write_pem_atomic(&path, b"ca", false).expect("write");
        assert_eq!(std::fs::read(&path).expect("read"), b"ca");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = std::fs::metadata(&path).expect("stat").permissions().mode();
            assert_ne!(mode & 0o777, 0o600, "the CA is not a secret");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A single address gets the whole remaining budget, and two addresses
    /// split it — so the total wait stays bounded by the budget no matter how
    /// many records DNS returns. Without the split, a blackholed AAAA would
    /// burn the entire budget and leave a reachable A record untried.
    #[test]
    fn budget_is_shared_between_addresses() {
        assert_eq!(
            connect_budget_slice(Duration::from_secs(10), 1),
            Duration::from_secs(10)
        );
        assert_eq!(
            connect_budget_slice(Duration::from_secs(10), 2),
            Duration::from_secs(5)
        );
        assert_eq!(
            connect_budget_slice(Duration::from_secs(9), 3),
            Duration::from_secs(3)
        );
    }

    /// `TcpStream::connect_timeout` REJECTS a zero duration, so a slice that
    /// rounds down to nothing would turn "almost out of time" into an instant
    /// hard failure rather than one last attempt. It must never be zero.
    #[test]
    fn slice_is_never_zero() {
        assert!(!connect_budget_slice(Duration::from_nanos(1), 64).is_zero());
        assert!(!connect_budget_slice(Duration::ZERO, 1).is_zero());
    }

    /// Zero addresses must not divide by zero. The connect loop cannot reach
    /// this (it iterates exactly `addrs.len()` times), but the guard is the
    /// reason it cannot, so it is pinned rather than assumed.
    #[test]
    fn zero_remaining_addresses_does_not_panic() {
        assert!(!connect_budget_slice(Duration::from_secs(1), 0).is_zero());
    }

    /// A reachable listener connects, and the budget does not interfere.
    #[test]
    fn connects_to_a_live_listener() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        tcp_connect_within(&addr.to_string(), Duration::from_secs(5)).expect("should connect");
    }

    /// A refused port reports the OS error, NOT a synthesised timeout — the
    /// distinction is what tells a user "nothing is listening there" apart
    /// from "I could not reach that host at all".
    #[test]
    fn refused_port_reports_the_os_error() {
        // Bind then drop: the port was just in use, so nothing is listening.
        let addr = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            l.local_addr().expect("local_addr")
        };
        let err = tcp_connect_within(&addr.to_string(), Duration::from_secs(5))
            .expect_err("nothing is listening");
        assert!(
            err.downcast_ref::<std::io::Error>().is_some(),
            "expected the underlying io::Error, got: {:#}",
            err
        );
        assert!(
            !format!("{err:#}").contains("timed out"),
            "a refusal must not be reported as a timeout: {:#}",
            err
        );
    }

    /// A name that resolves to nothing fails with a clear message instead of
    /// silently succeeding at "tried every address".
    #[test]
    fn unresolvable_name_is_an_error() {
        let err = tcp_connect_within("no-such-host.invalid:8443", Duration::from_secs(2))
            .expect_err("`.invalid` is reserved and must not resolve");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("no-such-host.invalid"),
            "unhelpful error: {}",
            msg
        );
    }
}
