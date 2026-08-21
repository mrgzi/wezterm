use crate::connui::ConnectionUI;
use crate::domain::{alloc_domain_id, Domain, DomainId, DomainState, WriterWrapper};
use crate::localpane::LocalPane;
use crate::pane::{alloc_pane_id, Pane, PaneId};
use crate::Mux;
use anyhow::{anyhow, bail, Context};
use async_trait::async_trait;
use config::{Shell, SshBackend, SshDomain};
use filedescriptor::{poll, pollfd, socketpair, AsRawSocketDescriptor, FileDescriptor, POLLIN};
use portable_pty::cmdbuilder::CommandBuilder;
use portable_pty::{ChildKiller, ExitStatus, MasterPty, PtySize};
use smol::channel::{bounded, Receiver as AsyncReceiver};
use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::{BufWriter, Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use termwiz::cell::{unicode_column_width, AttributeChange, Intensity};
use termwiz::input::{InputEvent, InputParser};
use termwiz::lineedit::*;
use termwiz::render::terminfo::TerminfoRenderer;
use termwiz::surface::{Change, LineAttribute};
use termwiz::terminal::{ScreenSize, Terminal, TerminalWaker};
use wezterm_ssh::{
    AuthPromptOrigin, ConfigMap, HostVerificationFailed, Session, SessionEvent, SshChildProcess,
    SshPty,
};
use wezterm_term::TerminalSize;

#[derive(Default)]
struct PasswordPromptHost {
    history: BasicHistory,
    echo: bool,
}
impl LineEditorHost for PasswordPromptHost {
    fn history(&mut self) -> &mut dyn History {
        &mut self.history
    }

    fn highlight_line(&self, line: &str, cursor_position: usize) -> (Vec<OutputElement>, usize) {
        if self.echo {
            (vec![OutputElement::Text(line.to_string())], cursor_position)
        } else {
            // Rewrite the input so that we can obscure the password
            // characters when output to the terminal widget
            let placeholder = "🔑";
            let grapheme_count = unicode_column_width(line, None);
            let mut output = vec![];
            for _ in 0..grapheme_count {
                output.push(OutputElement::Text(placeholder.to_string()));
            }
            (
                output,
                unicode_column_width(placeholder, None) * cursor_position,
            )
        }
    }
}

pub fn ssh_connect_with_ui(
    ssh_config: wezterm_ssh::ConfigMap,
    ui: &mut ConnectionUI,
) -> anyhow::Result<Session> {
    let cloned_ui = ui.clone();
    cloned_ui.run_and_log_error(move || {
        let remote_address = ssh_config
            .get("hostname")
            .expect("ssh config to always set hostname");
        ui.output_str(&format!("Connecting to {} using SSH\n", remote_address));
        let (session, events) = Session::connect(ssh_config.clone())?;

        while let Ok(event) = smol::block_on(events.recv()) {
            match event {
                SessionEvent::Banner(banner) => {
                    if let Some(banner) = banner {
                        ui.output_str(&format!("{}\n", banner));
                    }
                }
                SessionEvent::HostVerify(verify) => {
                    ui.output_str(&format!("{}\n", verify.message));
                    // The message also travels TYPED alongside the prompt:
                    // an embedded responder (ResponderImpl) must not have to
                    // recover it from the Output stream, where the
                    // server-controlled banner (printed above) could spoof a
                    // fingerprint-looking line. Overlay/headless UIs ignore
                    // the context; the output_str above keeps their display.
                    let ok =
                        if let Ok(line) = ui.input_with_context("Enter [y/n]> ", &verify.message) {
                            match line.as_ref() {
                                "y" | "Y" | "yes" | "YES" => true,
                                "n" | "N" | "no" | "NO" | _ => false,
                            }
                        } else {
                            false
                        };
                    smol::block_on(verify.answer(ok)).context("send verify response")?;
                }
                SessionEvent::Authenticate(auth) => {
                    if !auth.username.is_empty() {
                        ui.output_str(&format!("Authentication for {}\n", auth.username));
                    }
                    if !auth.instructions.is_empty() {
                        ui.output_str(&format!("{}\n", auth.instructions));
                    }
                    let mut answers = vec![];
                    for prompt in &auth.prompts {
                        let mut prompt_lines = prompt.prompt.split('\n').collect::<Vec<_>>();
                        let editor_prompt = prompt_lines.pop().unwrap();
                        for line in &prompt_lines {
                            ui.output_str(&format!("{}\n", line));
                        }
                        // Termob fork: a secret prompt carries WHERE IT CAME
                        // FROM, so an embedded responder can refuse to answer a
                        // server-composed prompt with a local-only secret (the
                        // passphrase of a key file on this machine). Text
                        // matching cannot substitute for this — over
                        // keyboard-interactive the server writes the prompt
                        // itself and would simply imitate the local wording.
                        let origin = match auth.origin {
                            AuthPromptOrigin::Local => crate::connui::AUTH_ORIGIN_LOCAL,
                            AuthPromptOrigin::Server => crate::connui::AUTH_ORIGIN_SERVER,
                        };
                        // The origin travels on the echoing branch too. Without
                        // it the context arrives as `None`, and the responder
                        // falls back to the buffered output — which the SERVER
                        // wrote. A prompt whose text happens to match the
                        // host-key question would then be handed to the
                        // host-key verifier with server-authored text as its
                        // fingerprint. Carrying the origin lets the responder
                        // tell an auth prompt from a real host verification,
                        // which is the only durable distinction: the text is
                        // the attacker's to choose.
                        let res = if prompt.echo {
                            ui.input_with_context(editor_prompt, origin)
                        } else {
                            ui.password_with_context(editor_prompt, origin)
                        };
                        if let Ok(line) = res {
                            answers.push(line);
                        } else {
                            anyhow::bail!("Authentication was cancelled");
                        }
                    }
                    smol::block_on(auth.answer(answers))?;
                }
                SessionEvent::HostVerificationFailed(failed) => {
                    let message = format_host_verification_for_terminal(failed);
                    ui.output(message);
                    anyhow::bail!("Host key verification failed");
                }
                SessionEvent::Error(err) => {
                    anyhow::bail!("Error: {}", err);
                }
                SessionEvent::Authenticated => return Ok(session),
            }
        }
        bail!("unable to authenticate session");
    })
}

fn format_host_verification_for_terminal(failed: HostVerificationFailed) -> Vec<Change> {
    vec![
        AttributeChange::Intensity(Intensity::Bold).into(),
        LineAttribute::DoubleHeightTopHalfLine.into(),
        Change::Text("REMOTE HOST IDENTIFICATION CHANGED\r\n".to_string()),
        LineAttribute::DoubleHeightBottomHalfLine.into(),
        Change::Text("REMOTE HOST IDENTIFICATION CHANGED\r\n".to_string()),
        Change::Text("SOMEONE MAY BE DOING SOMETHING NASTY!\r\n".to_string()),
        AttributeChange::Intensity(Intensity::Normal).into(),
        Change::Text("\r\nThere are two likely causes for this:\r\n".to_string()),
        Change::Text(
            " 1. Someone is eavesdropping right now (man-in-the-middle attack)\r\n".to_string(),
        ),
        Change::Text(" 2. The host key may have been changed by the administrator\r\n".to_string()),
        Change::Text("\r\n".to_string()),
        AttributeChange::Intensity(Intensity::Bold).into(),
        Change::Text(
            "Please contact your system administrator to discuss how to proceed!\r\n".to_string(),
        ),
        AttributeChange::Intensity(Intensity::Normal).into(),
        Change::Text("\r\n".to_string()),
        match failed.file {
            Some(file) => Change::Text(format!(
                "The host is {}, and its fingerprint is\r\n{}\r\n\
                If the administrator confirms that the key has changed, you can\r\n\
                fix this for yourself by removing the offending entry from\r\n\
                {} and then try connecting again.\r\n",
                failed.remote_address,
                failed.key,
                file.display(),
            )),
            None => Change::Text(format!(
                "The host is {}, and its fingerprint is\r\n{}\r\n",
                failed.remote_address, failed.key
            )),
        },
    ]
}

/// Represents a connection to remote host via ssh.
/// The domain is created with the ssh config prior to making the
/// connection.  The connection is established by the first spawn()
/// call.
/// In order to show the authentication dialog inline in that spawned
/// pane, we play some tricks with wrapped versions of the pty, child
/// and the reader and writer instances so that we can inject the
/// interactive setup.  The bulk of that is driven by `connect_ssh_session`.
pub struct RemoteSshDomain {
    session: Mutex<Option<Session>>,
    dom: SshDomain,
    id: DomainId,
    name: String,
    /// Termob fork: the password most recently supplied by the embedder, held
    /// apart from `dom` so that it can be replaced.
    ///
    /// A domain is never removed from the multiplexer, so a second connection
    /// to a host finds the entry the first one left — including an entry whose
    /// authentication failed. Reading the password out of `dom` would then
    /// re-use the FIRST attempt's, and the one the user has just typed would
    /// never be tried. See [`RemoteSshDomain::adopt_supplied_settings`].
    supplied_password: Mutex<Option<String>>,
    /// Termob fork: the `ssh_option`s most recently supplied by the embedder,
    /// held apart from `dom` for the reason `supplied_password` is — and for the
    /// same failure, one step further out.
    ///
    /// These are what the connection is MADE from: the identity files, the port,
    /// the keepalive. A domain outlives the connection it was built for
    /// ([`RemoteSshDomain::close_session`]), so a second connection to a host
    /// establishes a new one — and reading these out of `dom` would establish it
    /// with the first attempt's identity rather than the one the user has since
    /// chosen. See [`RemoteSshDomain::adopt_supplied_settings`].
    supplied_options: Mutex<HashMap<String, String>>,
    /// Termob fork: whether a connection this domain held has been closed.
    ///
    /// **What tells "closed" from "not connected yet".** Both leave `session`
    /// empty, and [`RemoteSshDomain::state`] answered `Attached` for the pair of
    /// them — so a domain whose connection the embedder had just closed reported
    /// itself as carrying, which is the one question that method exists to
    /// answer. Nothing reads it wrongly today only because the surface that
    /// would ask has gone by then; it is a wrong answer waiting for a caller.
    ///
    /// Set by [`RemoteSshDomain::close_session`] and cleared when a new session
    /// is established, so a domain reconnected through is `Attached` again.
    session_closed: AtomicBool,
    /// Termob fork: signalled when the first pane's pty is ready. See
    /// [`RemoteSshDomain::pty_ready`].
    pty_ready: (smol::channel::Sender<()>, smol::channel::Receiver<()>),
}

/// Termob fork: the `ssh_option` key carrying a password the embedder already
/// collected from the user.
///
/// It is answered to the server's first non-echoing authentication prompt
/// instead of the line editor this file runs inside the pane, so a connection
/// the user has already supplied a password for does not ask for it again.
///
/// **It is taken out of the map and never reaches the ssh config.** The config
/// is logged in full when `wezterm_ssh_verbose` is set, and wezterm-ssh has no
/// use for the value in any case.
pub const TERMOB_PASSWORD_OPTION: &str = "termob_password";

/// Termob fork: the password an [`SshDomain`] carries, if it carries one.
///
/// An empty value is the same thing as no value: the field the user left blank
/// must leave the prompt to the pane rather than answer it with nothing.
fn supplied_password_of(dom: &SshDomain) -> Option<String> {
    dom.ssh_option
        .get(TERMOB_PASSWORD_OPTION)
        .filter(|p| !p.is_empty())
        .cloned()
}

pub fn ssh_domain_to_ssh_config(ssh_dom: &SshDomain) -> anyhow::Result<ConfigMap> {
    let mut ssh_config = wezterm_ssh::Config::new();
    ssh_config.add_default_config_files();

    let (remote_host_name, port) = {
        let parts: Vec<&str> = ssh_dom.remote_address.split(':').collect();

        if parts.len() == 2 {
            (parts[0], Some(parts[1].parse::<u16>()?))
        } else {
            (ssh_dom.remote_address.as_str(), None)
        }
    };

    let mut ssh_config = ssh_config.for_host(&remote_host_name);
    ssh_config.insert(
        "wezterm_ssh_backend".to_string(),
        match ssh_dom
            .ssh_backend
            .unwrap_or_else(|| config::configuration().ssh_backend)
        {
            SshBackend::Ssh2 => "ssh2",
            SshBackend::LibSsh => "libssh",
        }
        .to_string(),
    );
    for (k, v) in &ssh_dom.ssh_option {
        // Termob fork: the password is for the auth responder in this file, not
        // for the ssh config — and the config below is logged in full when
        // `wezterm_ssh_verbose` is set.
        if k == TERMOB_PASSWORD_OPTION {
            continue;
        }
        ssh_config.insert(k.to_string(), v.to_string());
    }

    if let Some(username) = &ssh_dom.username {
        ssh_config.insert("user".to_string(), username.to_string());
    }
    if let Some(port) = port {
        ssh_config.insert("port".to_string(), port.to_string());
    }
    if ssh_dom.no_agent_auth {
        ssh_config.insert("identitiesonly".to_string(), "yes".to_string());
    }
    if let Some("true") = ssh_config.get("wezterm_ssh_verbose").map(|s| s.as_str()) {
        log::info!("Using ssh config: {ssh_config:#?}");
    }
    Ok(ssh_config)
}

impl RemoteSshDomain {
    pub fn with_ssh_domain(dom: &SshDomain) -> anyhow::Result<Self> {
        let id = alloc_domain_id();
        Ok(Self {
            id,
            name: dom.name.clone(),
            session: Mutex::new(None),
            supplied_password: Mutex::new(supplied_password_of(dom)),
            supplied_options: Mutex::new(dom.ssh_option.clone()),
            session_closed: AtomicBool::new(false),
            pty_ready: smol::channel::bounded(1),
            dom: dom.clone(),
        })
    }

    /// Termob fork: take this attempt's connection settings from `dom`,
    /// replacing whatever an earlier connection to this host left behind.
    ///
    /// Called before spawning on a domain the multiplexer already holds. A
    /// domain is never removed from the multiplexer, so it outlives the
    /// connection it was built for: once [`Self::close_session`] has run, the
    /// next spawn ESTABLISHES a connection rather than re-using one, and it must
    /// establish the connection the embedder is asking for now.
    ///
    /// This adopted the password alone, on the reasoning that a host already
    /// reached has its identity settled. That holds only while the connection is
    /// live. With it closed, a user who chose a key file and connected again was
    /// authenticated with the FIRST attempt's identity — commonly none at all —
    /// so the key they had just picked was never offered and the host asked for
    /// a password instead. Which of the two happened depended on whether
    /// anything had connected to that host earlier in the process, so it read as
    /// a key that worked sometimes.
    ///
    /// The address and the port cannot disagree here: the domain is looked up by
    /// a name the embedder derives from them. The rest of `dom` — the shell, the
    /// default program — is deliberately not adopted, because those describe
    /// what runs inside a pane rather than how the connection is made.
    pub fn adopt_supplied_settings(&self, dom: &SshDomain) {
        *self.supplied_password.lock().unwrap() = supplied_password_of(dom);
        *self.supplied_options.lock().unwrap() = dom.ssh_option.clone();
    }

    pub fn ssh_config(&self) -> anyhow::Result<ConfigMap> {
        // Termob fork: the options this attempt supplied, not the ones the
        // domain was built with — see [`Self::adopt_supplied_settings`].
        let mut dom = self.dom.clone();
        dom.ssh_option = self.supplied_options.lock().unwrap().clone();
        ssh_domain_to_ssh_config(&dom)
    }

    /// Returns a clone of the underlying SSH session handle, if the session
    /// has been established. The session is created lazily by the first
    /// `spawn_pane` (interactive auth happens inside that pane), so this
    /// returns `None` until a pane has been spawned. Embedders can use the
    /// handle to run auxiliary operations (eg: provisioning files over sftp)
    /// on the same authenticated connection.
    pub fn connected_session(&self) -> Option<Session> {
        self.session.lock().unwrap().clone()
    }

    /// Termob fork: close this domain's connection, and forget it.
    ///
    /// A domain is never removed from the multiplexer, so it outlives the
    /// connection it was built for and must be able to say so: the next
    /// `spawn_pane` then finds nothing to reuse and establishes a new one,
    /// rather than discovering through a failed request that what it held was a
    /// corpse.
    ///
    /// Nothing here decides WHEN — that is the embedder's, which is the only
    /// party that knows whether anything still wants the connection.
    ///
    /// Answers whether there was a connection to close. Several paths reach a
    /// closing tab and each of them asks; without an answer, every one of them
    /// reports having closed the connection that the first of them closed.
    pub fn close_session(&self) -> bool {
        match self.session.lock().unwrap().take() {
            Some(session) => {
                session.shutdown();
                // Recorded because taking the session leaves this domain
                // indistinguishable from one that never connected, and the two
                // owe opposite answers to `state`.
                self.session_closed.store(true, Ordering::Relaxed);
                true
            }
            None => false,
        }
    }

    /// Termob fork: resolves once this domain's first pane has a real pty.
    ///
    /// Everything an embedder asks this session for — sftp above all — is
    /// served on the one session thread, in the order it was queued, with the
    /// socket in blocking mode. Auxiliary work started when `spawn_pane`
    /// returns is therefore queued BEFORE the pty request, because that
    /// request is only made once authentication completes: it delays the first
    /// prompt by however long it takes, and a subsystem the far end is slow to
    /// open holds the prompt for as long as it blocks.
    ///
    /// Waiting on this puts that work behind the pane instead of in front of
    /// it. Capacity of one, filled with `force_send`: signalling never blocks
    /// the connection, a receiver that arrives late still finds the token, and
    /// what it finds is the most recent pty rather than one belonging to a
    /// session this domain has since replaced.
    pub fn pty_ready(&self) -> smol::channel::Receiver<()> {
        self.pty_ready.1.clone()
    }

    fn build_command(
        &self,
        pane_id: PaneId,
        command: Option<CommandBuilder>,
        command_dir: Option<String>,
    ) -> anyhow::Result<(Option<String>, HashMap<String, String>)> {
        let config = config::configuration();
        let cmd = match command {
            Some(mut cmd) => {
                config.apply_cmd_defaults(&mut cmd, self.dom.default_prog.as_ref(), None);
                cmd
            }
            None => config.build_prog(None, self.dom.default_prog.as_ref(), None)?,
        };
        let mut env: HashMap<String, String> = cmd
            .iter_extra_env_as_str()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();

        // FIXME: this isn't useful without a way to talk to the remote mux.
        // One option is to forward the mux via unix domain, another is to
        // embed the mux protocol in an escape sequence and just use the
        // existing terminal connection
        env.insert("WEZTERM_REMOTE_PANE".to_string(), pane_id.to_string());

        fn build_env_command(
            dir: Option<String>,
            cmd: &CommandBuilder,
            env: &HashMap<String, String>,
        ) -> anyhow::Result<String> {
            // "Soft" chdir: if it doesn't exist then it doesn't matter
            let cd_cmd = if let Some(dir) = dir {
                format!("cd {};", shell_words::quote(&dir))
            } else if let Some(dir) = cmd.get_cwd() {
                let dir = dir.to_str().context("converting cwd to string")?;
                format!("cd {};", shell_words::quote(&dir))
            } else {
                String::new()
            };

            let mut env_cmd = vec!["env".to_string()];

            for (k, v) in env {
                env_cmd.push(format!("{}={}", k, v));
            }

            let cmd = if cmd.is_default_prog() {
                // We'd like to spawn a login shell, but since we are invoking env
                // we end up in a regular shell.
                // This guff tries to find a reasonably portable way to execute
                // the shell as a login shell.
                // Per: <https://unix.stackexchange.com/a/666850/123914>
                // the most portable way is to use perl, but in case perl is not
                // installed, zsh, bash and ksh all support `exec -a`.
                // Other shells may support `exec -a` but there isn't a simple
                // way to test for them, so we assume that if we have one of those
                // three that we can use it, otherwise we fall back to just running
                // the shell directly.
                let login_shell = "command -v perl > /dev/null && \
                  exec perl -e 'use File::Basename; $shell = basename($ENV{SHELL}); exec {$ENV{SHELL}} \"-$shell\"'; \
                  case \"$SHELL\" in */zsh|*/bash|*/ksh ) exec -a \"-$(basename $SHELL)\" $SHELL ;; esac ; \
                  exec $SHELL";

                format!("$SHELL -c {}", shell_words::quote(login_shell))
            } else {
                cmd.as_unix_command_line()?
            };

            Ok(cd_cmd + &shell_words::join(env_cmd) + " " + &cmd)
        }

        // Where the environment has been folded into the command line, it is
        // NOT also handed back to be requested one variable at a time.
        //
        // `build_env_command` prefixes the command with `env K=V ...`, which
        // is the whole point of knowing the shell is POSIX — the values are
        // already on their way. Returning the same map as well made `new_pty`
        // send a `setenv` channel request for each of them, and a channel
        // request is a round trip. A default `sshd` refuses all of them
        // (`AcceptEnv` lists none of these names), so the connection paid five
        // round trips to be told "no" five times, having already delivered the
        // values by a route that works. Measured at 0.76 s of a 5.2 s
        // connection to a host 150 ms away, and paid again by every split.
        let (command_line, env) = match (cmd.is_default_prog(), self.dom.assume_shell, command_dir) {
            (_, Shell::Posix, dir) => (
                Some(build_env_command(dir, &cmd, &env)?),
                HashMap::new(),
            ),
            (true, _, _) => (None, env),
            (false, _, _) => (Some(cmd.as_unix_command_line()?), env),
        };

        Ok((command_line, env))
    }

    async fn start_new_session(
        &self,
        command_line: Option<String>,
        env: HashMap<String, String>,
        size: TerminalSize,
    ) -> anyhow::Result<StartNewSessionResult> {
        let (session, events) = Session::connect(self.ssh_config().context("obtain ssh config")?)
            .context("connect to ssh server")?;
        self.session.lock().unwrap().replace(session.clone());
        // Termob fork: this domain is carrying again, so whatever it closed
        // before stops being what `state` reports. Ordered after the session is
        // in place, so no reader can find the flag down with nothing behind it.
        self.session_closed.store(false, Ordering::Relaxed);

        // We get to establish the session!
        //
        // Since we want spawn to return the Pane in which
        // we'll carry out interactive auth, we generate
        // some shim/wrapper versions of the pty, child
        // and reader/writer.

        let (stdout_read, stdout_write) = socketpair()?;
        let (reader_tx, reader_rx) = channel();
        let (stdin_read, stdin_write) = socketpair()?;
        let (writer_tx, writer_rx) = channel();

        let pty_reader = PtyReader {
            reader: Box::new(stdout_read),
            rx: reader_rx,
        };

        let pty_writer = PtyWriter {
            writer: Box::new(stdin_write),
            rx: writer_rx,
        };
        let writer = Box::new(pty_writer);

        let (child_tx, child_rx) = channel();

        let child = Box::new(WrappedSshChild {
            status: None,
            rx: child_rx,
            exited: None,
            killer: WrappedSshChildKiller {
                inner: Arc::new(Mutex::new(KillerInner {
                    killer: None,
                    pending_kill: false,
                })),
            },
        });

        let (pty_tx, pty_rx) = channel();

        let size = Arc::new(Mutex::new(size));

        let pty = Box::new(WrappedSshPty {
            inner: RefCell::new(WrappedSshPtyInner::Connecting {
                size: Arc::clone(&size),
                reader: Some(pty_reader),
                connected: pty_rx,
            }),
        });

        // And with those created, we can now spawn a new thread
        // to perform the blocking (from its perspective) terminal
        // UI to carry out any authentication.
        let mut stdout_write = BufWriter::new(stdout_write);
        // Termob fork: read the password the embedder supplied rather than the
        // ssh config, which deliberately never carries it — see
        // `TERMOB_PASSWORD_OPTION`. It is taken from the domain's own field
        // rather than from `dom`, so that a further attempt against a host this
        // domain already stands for uses the secret typed for THAT attempt; see
        // `adopt_supplied_settings`.
        let supplied_password = self.supplied_password.lock().unwrap().clone();
        let pty_ready_tx = self.pty_ready.0.clone();
        std::thread::spawn(move || {
            if let Err(err) = connect_ssh_session(
                session,
                events,
                stdin_read,
                writer_tx,
                &mut stdout_write,
                reader_tx,
                child_tx,
                pty_tx,
                size,
                command_line,
                env,
                supplied_password,
                pty_ready_tx,
            ) {
                let _ = write!(stdout_write, "{:#}", err);
                log::error!("Failed to connect ssh: {:#}", err);
            }
            let _ = stdout_write.flush();
        });

        Ok(StartNewSessionResult { pty, child, writer })
    }
}

struct StartNewSessionResult {
    pty: Box<dyn portable_pty::MasterPty + Send>,
    child: Box<dyn portable_pty::Child + Send>,
    writer: BoxedWriter,
}

/// Carry out the authentication process and create the initial pty.
fn connect_ssh_session(
    session: Session,
    events: smol::channel::Receiver<SessionEvent>,
    mut stdin_read: FileDescriptor,
    stdin_tx: Sender<BoxedWriter>,
    stdout_write: &mut BufWriter<FileDescriptor>,
    stdout_tx: Sender<BoxedReader>,
    child_tx: Sender<SshChildProcess>,
    pty_tx: Sender<SshPty>,
    size: Arc<Mutex<TerminalSize>>,
    command_line: Option<String>,
    env: HashMap<String, String>,
    // Termob fork: a password the embedder already has, answered to the first
    // non-echoing prompt. See `TERMOB_PASSWORD_OPTION`.
    mut supplied_password: Option<String>,
    // Termob fork: signalled once the pty exists, so that an embedder's own
    // work on this session queues behind it. See `RemoteSshDomain::pty_ready`.
    pty_ready_tx: smol::channel::Sender<()>,
) -> anyhow::Result<()> {
    struct StdoutShim<'a> {
        size: Arc<Mutex<TerminalSize>>,
        stdout: &'a mut BufWriter<FileDescriptor>,
    }

    impl<'a> Write for StdoutShim<'a> {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.stdout.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.stdout.flush()
        }
    }

    impl<'a> termwiz::render::RenderTty for StdoutShim<'a> {
        fn get_size_in_cells(&mut self) -> termwiz::Result<(usize, usize)> {
            let size = *self.size.lock().unwrap();
            Ok((size.cols as _, size.rows as _))
        }
    }

    /// a termwiz Terminal for use with the line editor
    struct TerminalShim<'a> {
        stdout: &'a mut StdoutShim<'a>,
        stdin: &'a mut FileDescriptor,
        size: Arc<Mutex<TerminalSize>>,
        renderer: TerminfoRenderer,
        parser: InputParser,
        input_queue: VecDeque<InputEvent>,
    }

    impl<'a> termwiz::terminal::Terminal for TerminalShim<'a> {
        fn set_raw_mode(&mut self) -> termwiz::Result<()> {
            use termwiz::escape::csi::{DecPrivateMode, DecPrivateModeCode, Mode, CSI};

            macro_rules! decset {
                ($variant:ident) => {
                    write!(
                        self.stdout,
                        "{}",
                        CSI::Mode(Mode::SetDecPrivateMode(DecPrivateMode::Code(
                            DecPrivateModeCode::$variant
                        )))
                    )?;
                };
            }

            decset!(BracketedPaste);
            self.flush()?;

            Ok(())
        }

        fn flush(&mut self) -> termwiz::Result<()> {
            self.stdout.flush()?;
            Ok(())
        }

        fn set_cooked_mode(&mut self) -> termwiz::Result<()> {
            Ok(())
        }

        fn enter_alternate_screen(&mut self) -> termwiz::Result<()> {
            termwiz::bail!("TerminalShim has no alt screen");
        }

        fn exit_alternate_screen(&mut self) -> termwiz::Result<()> {
            termwiz::bail!("TerminalShim has no alt screen");
        }

        fn get_screen_size(&mut self) -> termwiz::Result<ScreenSize> {
            let size = *self.size.lock().unwrap();
            Ok(ScreenSize {
                cols: size.cols as _,
                rows: size.rows as _,
                xpixel: size.pixel_width as _,
                ypixel: size.pixel_height as _,
            })
        }

        fn set_screen_size(&mut self, _size: ScreenSize) -> termwiz::Result<()> {
            termwiz::bail!("TerminalShim cannot set screen size");
        }

        fn render(&mut self, changes: &[Change]) -> termwiz::Result<()> {
            self.renderer.render_to(changes, self.stdout)?;
            Ok(())
        }

        fn poll_input(&mut self, wait: Option<Duration>) -> termwiz::Result<Option<InputEvent>> {
            if let Some(event) = self.input_queue.pop_front() {
                return Ok(Some(event));
            }

            let deadline = wait.map(|d| Instant::now() + d);
            let starting_size = *self.size.lock().unwrap();

            self.stdin.set_non_blocking(true)?;

            loop {
                if let Some(deadline) = deadline.as_ref() {
                    if Instant::now() >= *deadline {
                        return Ok(None);
                    }
                }
                let mut pfd = [pollfd {
                    fd: self.stdin.as_socket_descriptor(),
                    events: POLLIN,
                    revents: 0,
                }];

                if let Ok(1) = poll(&mut pfd, Some(Duration::from_millis(200))) {
                    let mut buf = [0u8; 64];
                    let n = self.stdin.read(&mut buf)?;
                    let input_queue = &mut self.input_queue;
                    self.parser
                        .parse(&buf[0..n], |evt| input_queue.push_back(evt), n == buf.len());
                    return Ok(self.input_queue.pop_front());
                } else {
                    let size = *self.size.lock().unwrap();
                    if starting_size != size {
                        return Ok(Some(InputEvent::Resized {
                            cols: size.cols as usize,
                            rows: size.rows as usize,
                        }));
                    }
                }
            }
        }

        fn waker(&self) -> TerminalWaker {
            // TODO: TerminalWaker assumes that we're a SystemTerminal but that
            // isn't the case here.
            panic!("TerminalShim::waker called!?");
        }
    }

    let renderer = termwiz_funcs::new_wezterm_terminfo_renderer();
    let mut shim = TerminalShim {
        stdout: &mut StdoutShim {
            stdout: stdout_write,
            size: Arc::clone(&size),
        },
        size: Arc::clone(&size),
        renderer,
        stdin: &mut stdin_read,
        parser: InputParser::new(),
        input_queue: VecDeque::new(),
    };

    impl<'a> TerminalShim<'a> {
        fn output_line(&mut self, s: &str) -> termwiz::Result<()> {
            let mut s = s.replace("\n", "\r\n");
            s.push_str("\r\n");
            self.render(&[Change::Text(s)])
        }
    }

    // Where the wait between pressing "connect" and seeing a prompt actually
    // goes.
    //
    // Everything the embedder can time itself finishes in milliseconds — the
    // domain is registered, this thread is started, and the pane is handed
    // back before a single packet has been exchanged. The whole of the
    // perceived delay is inside this loop: the transport handshake, then as
    // many authentication round trips as the server asks for, then the pty
    // request. Without these two lines the only honest answer to "why is
    // connecting slow" is a guess, so they are permanent rather than
    // temporary, and at `info` because one line per connection is not a per-
    // frame cost.
    let connect_started = std::time::Instant::now();

    // Process authentication related events
    while let Ok(event) = smol::block_on(events.recv()) {
        match event {
            SessionEvent::Banner(banner) => {
                if let Some(banner) = banner {
                    shim.output_line(&banner)?;
                }
            }
            SessionEvent::HostVerify(verify) => {
                shim.output_line(&verify.message)?;
                let mut editor = LineEditor::new(&mut shim);
                let mut host = PasswordPromptHost::default();
                host.echo = true;
                editor.set_prompt("Enter [y/n]> ");
                let ok = if let Some(line) = editor.read_line(&mut host)? {
                    match line.as_ref() {
                        "y" | "Y" | "yes" | "YES" => true,
                        "n" | "N" | "no" | "NO" | _ => false,
                    }
                } else {
                    false
                };
                smol::block_on(verify.answer(ok)).context("send verify response")?;
            }
            SessionEvent::Authenticate(auth) => {
                if !auth.username.is_empty() {
                    shim.output_line(&format!("Authentication for {}", auth.username))?;
                }
                if !auth.instructions.is_empty() {
                    shim.output_line(&auth.instructions)?;
                }
                let mut answers = vec![];
                for prompt in &auth.prompts {
                    // Termob fork: a password the embedder collected answers the
                    // first prompt that hides what is typed. `take` rather than
                    // a clone on purpose — a password the server refuses would
                    // otherwise be offered to every retry in turn and the user
                    // would never be asked, so the second prompt falls through
                    // to the line editor below.
                    if !prompt.echo {
                        if let Some(password) = supplied_password.take() {
                            answers.push(password);
                            continue;
                        }
                    }
                    let mut prompt_lines = prompt.prompt.split('\n').collect::<Vec<_>>();
                    let editor_prompt = prompt_lines.pop().unwrap();
                    for line in &prompt_lines {
                        shim.output_line(line)?;
                    }
                    let mut editor = LineEditor::new(&mut shim);
                    let mut host = PasswordPromptHost::default();
                    editor.set_prompt(editor_prompt);
                    host.echo = prompt.echo;
                    if let Some(line) = editor.read_line(&mut host)? {
                        answers.push(line);
                    } else {
                        anyhow::bail!("Authentication was cancelled");
                    }
                }
                smol::block_on(auth.answer(answers))?;
            }
            SessionEvent::Error(err) => {
                shim.output_line(&format!("Error: {}", err))?;
            }
            SessionEvent::HostVerificationFailed(failed) => {
                let message = format_host_verification_for_terminal(failed);
                shim.render(&message)?;
            }
            SessionEvent::Authenticated => {
                log::info!(
                    "ssh authenticated after {:?}",
                    connect_started.elapsed()
                );
                // Our session has been authenticated: we can now
                // set up the real pty for the pane
                match smol::block_on(session.request_pty(
                    &config::configuration().term,
                    crate::terminal_size_to_pty_size(*size.lock().unwrap())?,
                    command_line.as_ref().map(|s| s.as_str()),
                    Some(env),
                )) {
                    Err(err) => {
                        shim.output_line(&format!("Failed to spawn command: {:#}", err))?;
                        break;
                    }
                    Ok((pty, child)) => {
                        log::info!("ssh pty ready after {:?}", connect_started.elapsed());
                        // Termob fork: release anything waiting to use this
                        // session for work of its own. `force_send` rather than
                        // `try_send`: the domain outlives the session, so a
                        // token left there by an earlier connection's pty would
                        // otherwise answer for this one — and the waiter would
                        // go ahead before the pane it is meant to queue behind.
                        // Replacing it keeps the signal about the pty that has
                        // just been granted.
                        let _ = pty_ready_tx.force_send(());
                        drop(shim);

                        // Obtain the real stdin/stdout for the pty
                        let reader = pty.try_clone_reader()?;
                        let writer = pty.take_writer()?;

                        // And send them to the wrapped reader/writer
                        stdin_tx
                            .send(Box::new(writer))
                            .map_err(|e| anyhow!("{:#}", e))?;
                        stdout_tx
                            .send(Box::new(reader))
                            .map_err(|e| anyhow!("{:#}", e))?;

                        // Likewise, send the real pty and child to
                        // the wrappers
                        pty_tx.send(pty)?;
                        child_tx.send(child)?;

                        // Now when we return, our stdin_read and
                        // stdout_write will close and that will cause
                        // the PtyReader and PtyWriter to recv the
                        // the new reader/writer above and continue.
                        //
                        // The pty and child will be picked up when
                        // they are next polled or resized.

                        return Ok(());
                    }
                }
            }
        }
    }

    Ok(())
}

#[async_trait(?Send)]
impl Domain for RemoteSshDomain {
    async fn spawn_pane(
        &self,
        size: TerminalSize,
        command: Option<CommandBuilder>,
        command_dir: Option<String>,
    ) -> anyhow::Result<Arc<dyn Pane>> {
        let pane_id = alloc_pane_id();

        let (command_line, env) = self
            .build_command(pane_id, command, command_dir)
            .context("build_command")?;

        // This needs to be separate from the if let block below in order
        // for the lock to be released at the appropriate time
        let mut session: Option<Session> = self.session.lock().unwrap().as_ref().cloned();

        let StartNewSessionResult { pty, child, writer } = if let Some(session) = session.take() {
            match session
                .request_pty(
                    &config::configuration().term,
                    crate::terminal_size_to_pty_size(size)
                        .context("compute pty size from terminal size")?,
                    command_line.as_ref().map(|s| s.as_str()),
                    Some(env.clone()),
                )
                .await
                .context("request ssh pty")
            {
                Ok((concrete_pty, concrete_child)) => {
                    let pty = Box::new(concrete_pty);
                    let child = Box::new(concrete_child);
                    let writer = Box::new(pty.take_writer().context("take writer from pty")?);

                    StartNewSessionResult { pty, child, writer }
                }
                Err(err) => {
                    if err
                        .root_cause()
                        .downcast_ref::<wezterm_ssh::DeadSession>()
                        .is_some()
                    {
                        // Session died (perhaps they closed the initial tab?)
                        // So we'll try making a new one
                        self.start_new_session(command_line, env, size).await?
                    } else {
                        log::error!("{err:#?}");
                        return Err(err);
                    }
                }
            }
        } else {
            self.start_new_session(command_line, env, size).await?
        };

        // Wrap up the pty etc. in a LocalPane.  That allows for
        // eg: tmux integration to be tunnelled via the remote
        // session without duplicating a lot of logic over here.

        let writer = WriterWrapper::new(writer);

        let terminal = wezterm_term::Terminal::new(
            size,
            std::sync::Arc::new(config::TermConfig::new()),
            "WezTerm",
            config::wezterm_version(),
            Box::new(writer.clone()),
        );

        let pane: Arc<dyn Pane> = Arc::new(LocalPane::new(
            pane_id,
            terminal,
            child,
            pty,
            Box::new(writer),
            self.id,
            "RemoteSshDomain".to_string(),
        ));
        let mux = Mux::get();
        mux.add_pane(&pane)?;

        Ok(pane)
    }

    fn domain_id(&self) -> DomainId {
        self.id
    }

    fn domain_name(&self) -> &str {
        &self.name
    }

    async fn attach(&self, _window_id: Option<crate::WindowId>) -> anyhow::Result<()> {
        Ok(())
    }

    fn detachable(&self) -> bool {
        false
    }

    fn detach(&self) -> anyhow::Result<()> {
        bail!("detach not implemented for RemoteSshDomain");
    }

    fn state(&self) -> DomainState {
        // Termob fork: a connection that has ended says so.
        //
        // Upstream answered `Attached` unconditionally, on the grounds that
        // there is no attach operation distinct from a spawn. That is true of
        // ATTACHING and says nothing about having been DETACHED: the answer
        // stayed `Attached` after the transport was lost, so the one thing an
        // embedder can ask about a connection's health always said it was
        // healthy, and a session whose host had gone was indistinguishable
        // from one that was merely quiet.
        //
        // A domain that has not connected yet keeps upstream's answer. Nothing
        // has been lost there, and reporting a target as disconnected in the
        // moment before its first pane exists would announce a failure that
        // has not happened.
        //
        // A domain whose connection was CLOSED is the other empty case and owes
        // the opposite answer: it did carry one and does not now. The two are
        // told apart by `session_closed`, because taking the session leaves no
        // trace of there having been one.
        match self.session.lock().unwrap().as_ref() {
            Some(session) if !session.is_alive() => DomainState::Detached,
            None if self.session_closed.load(Ordering::Relaxed) => DomainState::Detached,
            _ => DomainState::Attached,
        }
    }
}

#[derive(Debug)]
struct KillerInner {
    killer: Option<Box<dyn ChildKiller + Send + Sync>>,
    /// If we haven't populated `killer` by the time someone has called
    /// `kill`, then we use this to remember to kill as soon as we recv
    /// the child process.
    pending_kill: bool,
}

#[derive(Debug, Clone)]
struct WrappedSshChildKiller {
    inner: Arc<Mutex<KillerInner>>,
}

#[derive(Debug)]
pub(crate) struct WrappedSshChild {
    status: Option<AsyncReceiver<ExitStatus>>,
    rx: Receiver<SshChildProcess>,
    exited: Option<ExitStatus>,
    killer: WrappedSshChildKiller,
}

impl WrappedSshChild {
    fn check_connected(&mut self) {
        if self.status.is_none() {
            match self.rx.try_recv() {
                Ok(c) => {
                    self.got_child(c);
                }
                Err(TryRecvError::Empty) => {}
                Err(err) => {
                    log::debug!("WrappedSshChild::check_connected err: {:#?}", err);
                    self.exited.replace(ExitStatus::with_exit_code(1));
                }
            }
        }
    }

    fn got_child(&mut self, mut child: SshChildProcess) {
        {
            let mut killer = self.killer.inner.lock().unwrap();
            killer.killer.replace(child.clone_killer());
            if killer.pending_kill {
                let _ = child.kill().ok();
            }
        }

        let (tx, rx) = bounded(1);
        promise::spawn::spawn_into_main_thread(async move {
            if let Ok(status) = child.async_wait().await {
                tx.send(status).await.ok();
                let mux = Mux::get();
                mux.prune_dead_windows();
            }
        })
        .detach();
        self.status.replace(rx);
    }
}

impl portable_pty::Child for WrappedSshChild {
    fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        if let Some(status) = self.exited.as_ref() {
            return Ok(Some(status.clone()));
        }

        self.check_connected();

        if let Some(rx) = self.status.as_mut() {
            match rx.try_recv() {
                Ok(status) => {
                    self.exited.replace(status.clone());
                    Ok(Some(status))
                }
                Err(smol::channel::TryRecvError::Empty) => Ok(None),
                Err(err) => {
                    log::debug!("WrappedSshChild::try_wait err: {:#?}", err);
                    let status = ExitStatus::with_exit_code(1);
                    self.exited.replace(status.clone());
                    Ok(Some(status))
                }
            }
        } else {
            Ok(None)
        }
    }

    fn wait(&mut self) -> std::io::Result<portable_pty::ExitStatus> {
        if let Some(status) = self.exited.as_ref() {
            return Ok(status.clone());
        }

        if self.status.is_none() {
            match smol::block_on(async { self.rx.recv() }) {
                Ok(c) => {
                    self.got_child(c);
                }
                Err(err) => {
                    log::debug!("WrappedSshChild err: {:#?}", err);
                    let status = ExitStatus::with_exit_code(1);
                    self.exited.replace(status.clone());
                    return Ok(status);
                }
            }
        }

        let rx = self.status.as_mut().unwrap();
        match smol::block_on(rx.recv()) {
            Ok(status) => {
                self.exited.replace(status.clone());
                Ok(status)
            }
            Err(err) => {
                log::error!("WrappedSshChild err: {:#?}", err);
                let status = ExitStatus::with_exit_code(1);
                self.exited.replace(status.clone());
                Ok(status)
            }
        }
    }

    fn process_id(&self) -> Option<u32> {
        None
    }

    #[cfg(windows)]
    fn as_raw_handle(&self) -> Option<std::os::windows::io::RawHandle> {
        None
    }
}

impl ChildKiller for WrappedSshChild {
    fn kill(&mut self) -> std::io::Result<()> {
        let mut killer = self.killer.inner.lock().unwrap();
        if let Some(killer) = killer.killer.as_mut() {
            killer.kill()
        } else {
            killer.pending_kill = true;
            Ok(())
        }
    }

    fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
        Box::new(self.killer.clone())
    }
}

impl ChildKiller for WrappedSshChildKiller {
    fn kill(&mut self) -> std::io::Result<()> {
        let mut killer = self.inner.lock().unwrap();
        if let Some(killer) = killer.killer.as_mut() {
            killer.kill()
        } else {
            killer.pending_kill = true;
            Ok(())
        }
    }

    fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
        Box::new(self.clone())
    }
}

type BoxedReader = Box<dyn Read + Send + 'static>;
type BoxedWriter = Box<dyn Write + Send + 'static>;

pub(crate) struct WrappedSshPty {
    inner: RefCell<WrappedSshPtyInner>,
}

impl WrappedSshPty {
    pub fn is_connecting(&mut self) -> bool {
        self.inner.borrow_mut().is_connecting()
    }
}

enum WrappedSshPtyInner {
    Connecting {
        reader: Option<PtyReader>,
        connected: Receiver<SshPty>,
        size: Arc<Mutex<TerminalSize>>,
    },
    Connected {
        reader: Option<PtyReader>,
        pty: SshPty,
    },
}

struct PtyReader {
    reader: BoxedReader,
    rx: Receiver<BoxedReader>,
}

struct PtyWriter {
    writer: BoxedWriter,
    rx: Receiver<BoxedWriter>,
}

impl WrappedSshPtyInner {
    fn check_connected(&mut self) -> anyhow::Result<()> {
        match self {
            Self::Connecting {
                reader,
                connected,
                size,
                ..
            } => {
                if let Ok(pty) = connected.try_recv() {
                    let res = pty.resize(crate::terminal_size_to_pty_size(*size.lock().unwrap())?);
                    *self = Self::Connected {
                        pty,
                        reader: reader.take(),
                    };
                    res
                } else {
                    Ok(())
                }
            }
            _ => Ok(()),
        }
    }

    fn is_connecting(&mut self) -> bool {
        self.check_connected().ok();
        match self {
            Self::Connecting { .. } => true,
            Self::Connected { .. } => false,
        }
    }
}

impl portable_pty::MasterPty for WrappedSshPty {
    fn resize(&self, new_size: PtySize) -> anyhow::Result<()> {
        let mut inner = self.inner.borrow_mut();
        match &mut *inner {
            WrappedSshPtyInner::Connecting { ref mut size, .. } => {
                {
                    let mut size = size.lock().unwrap();
                    size.cols = new_size.cols as usize;
                    size.rows = new_size.rows as usize;
                    size.pixel_height = new_size.pixel_height as usize;
                    size.pixel_width = new_size.pixel_width as usize;
                }
                inner.check_connected()
            }
            WrappedSshPtyInner::Connected { pty, .. } => pty.resize(new_size),
        }
    }

    fn get_size(&self) -> anyhow::Result<PtySize> {
        let mut inner = self.inner.borrow_mut();
        match &*inner {
            WrappedSshPtyInner::Connecting { size, .. } => {
                let size = crate::terminal_size_to_pty_size(*size.lock().unwrap())?;
                inner.check_connected()?;
                Ok(size)
            }
            WrappedSshPtyInner::Connected { pty, .. } => pty.get_size(),
        }
    }

    fn try_clone_reader(&self) -> anyhow::Result<Box<dyn Read + Send + 'static>> {
        let mut inner = self.inner.borrow_mut();
        inner.check_connected()?;
        match &mut *inner {
            WrappedSshPtyInner::Connected { ref mut reader, .. }
            | WrappedSshPtyInner::Connecting { ref mut reader, .. } => match reader.take() {
                Some(r) => Ok(Box::new(r)),
                None => anyhow::bail!("reader already taken"),
            },
        }
    }

    fn take_writer(&self) -> anyhow::Result<Box<dyn Write + Send + 'static>> {
        anyhow::bail!("writer must be created during bootstrap");
    }

    #[cfg(unix)]
    fn process_group_leader(&self) -> Option<i32> {
        let mut inner = self.inner.borrow_mut();
        let _ = inner.check_connected();
        None
    }

    #[cfg(unix)]
    fn as_raw_fd(&self) -> Option<std::os::fd::RawFd> {
        None
    }

    #[cfg(unix)]
    fn tty_name(&self) -> Option<std::path::PathBuf> {
        None
    }
}

impl std::io::Write for PtyWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Check for a new writer first: on Windows, the socket
        // will let us successfully write a byte to a disconnected
        // socket and we won't discover the issue until we write
        // the next byte.
        // <https://github.com/wezterm/wezterm/issues/771>
        if let Ok(writer) = self.rx.try_recv() {
            self.writer = writer;
        }
        self.writer.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.writer.flush() {
            Ok(_) => Ok(()),
            res => match self.rx.recv() {
                Ok(writer) => {
                    self.writer = writer;
                    self.writer.flush()
                }
                _ => res,
            },
        }
    }
}

impl std::io::Read for PtyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.reader.read(buf) {
            Ok(len) if len > 0 => Ok(len),
            res => match self.rx.recv() {
                Ok(reader) => {
                    self.reader = reader;
                    self.reader.read(buf)
                }
                _ => res,
            },
        }
    }
}
