use crate::termwiztermtab;
use anyhow::{anyhow, bail, Context as _};
use crossbeam::channel::{unbounded, Receiver, Sender};
use finl_unicode::grapheme_clusters::Graphemes;
use promise::spawn::block_on;
use promise::Promise;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use termwiz::cell::{unicode_column_width, CellAttributes};
use termwiz::lineedit::*;
use termwiz::surface::{Change, Position};
use termwiz::terminal::*;
use wezterm_term::TerminalSize;

#[derive(Default)]
struct PasswordPromptHost {
    history: BasicHistory,
}
impl LineEditorHost for PasswordPromptHost {
    fn history(&mut self) -> &mut dyn History {
        &mut self.history
    }

    // Rewrite the input so that we can obscure the password
    // characters when output to the terminal widget
    fn highlight_line(&self, line: &str, cursor_position: usize) -> (Vec<OutputElement>, usize) {
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

/// Context value marking an authentication prompt composed on THIS machine
/// (a key-file passphrase). A secret answered here never leaves the client.
///
/// Termob fork. Paired with [`AUTH_ORIGIN_SERVER`]; both are `const` so the
/// producer (`mux::ssh`) and the consumer (`termob-core`'s auth responder)
/// agree on one spelling instead of duplicating a literal that could drift
/// apart silently. See [`ConnectionUI::password_with_context`].
pub const AUTH_ORIGIN_LOCAL: &str = "auth-origin:local";

/// Context value marking an authentication prompt RELAYED FROM THE REMOTE
/// HOST (keyboard-interactive, password auth). Its text is chosen by the
/// server, so a responder must not answer it with a local-only secret.
pub const AUTH_ORIGIN_SERVER: &str = "auth-origin:server";

pub enum UIRequest {
    /// Display something
    Output(Vec<Change>),
    /// Request input
    Input {
        prompt: String,
        echo: bool,
        /// Typed provenance for what this prompt refers to, when the caller
        /// has it (see [`ConnectionUI::input_with_context`]). Host-key
        /// verification passes the client-computed host/fingerprint message
        /// here so an embedded responder does not have to recover it from the
        /// accumulated `Output` stream, where it would sit next to
        /// server-controlled text such as the SSH banner — which arrives
        /// *before* verification and could spoof a fingerprint-looking line.
        /// Terminal-overlay and headless impls ignore this field.
        ///
        /// **The meaning depends on `echo`, and a new caller must not mix the
        /// two.** With `echo = true` it is the host-key fingerprint message
        /// above; with `echo = false` it is one of
        /// [`AUTH_ORIGIN_LOCAL`] / [`AUTH_ORIGIN_SERVER`], saying who composed
        /// a secret prompt (see [`ConnectionUI::password_with_context`]).
        /// Responders branch on `echo` first, so the two never meet — but a
        /// third meaning added here would silently collide with one of them.
        context: Option<String>,
        respond: Promise<String>,
    },
    /// Sleep with a progress bar
    Sleep {
        reason: String,
        duration: Duration,
        respond: Promise<()>,
    },
    Close,
}

struct ConnectionUIImpl {
    term: termwiztermtab::TermWizTerminal,
    rx: Receiver<UIRequest>,
}

#[derive(PartialEq, Eq)]
enum CloseStatus {
    Explicit,
    Implicit,
}

impl ConnectionUIImpl {
    fn run(&mut self) -> anyhow::Result<CloseStatus> {
        loop {
            match self.rx.recv_timeout(Duration::from_millis(200)) {
                Ok(UIRequest::Close) => return Ok(CloseStatus::Explicit),
                Ok(UIRequest::Output(changes)) => self.term.render(&changes)?,
                Ok(UIRequest::Input {
                    prompt,
                    echo: true,
                    mut respond,
                    ..
                }) => {
                    respond.result(self.input_prompt(&prompt));
                }
                Ok(UIRequest::Input {
                    prompt,
                    echo: false,
                    mut respond,
                    ..
                }) => {
                    respond.result(self.password_prompt(&prompt));
                }
                Ok(UIRequest::Sleep {
                    reason,
                    duration,
                    mut respond,
                }) => {
                    respond.result(self.sleep(&reason, duration));
                }
                Err(err) if err.is_timeout() => {}
                Err(err) => bail!("recv_timeout: {}", err),
            }
        }
    }

    fn password_prompt(&mut self, prompt: &str) -> anyhow::Result<String> {
        let mut editor = LineEditor::new(&mut self.term);
        editor.set_prompt(prompt);

        let mut host = PasswordPromptHost::default();
        if let Some(line) = editor.read_line(&mut host)? {
            Ok(line)
        } else {
            bail!("password entry was cancelled");
        }
    }

    fn input_prompt(&mut self, prompt: &str) -> anyhow::Result<String> {
        let mut editor = LineEditor::new(&mut self.term);
        editor.set_prompt(prompt);

        let mut host = NopLineEditorHost::default();
        if let Some(line) = editor.read_line(&mut host)? {
            Ok(line)
        } else {
            bail!("prompt cancelled");
        }
    }

    fn sleep(&mut self, reason: &str, duration: Duration) -> anyhow::Result<()> {
        let start = Instant::now();
        let deadline = start + duration;
        let mut last_draw = None;

        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }

            // Render a progress bar underneath the countdown text by reversing
            // out the text for the elapsed portion of time.
            let remain = deadline - now;
            let term_width = self.term.get_screen_size().map(|s| s.cols).unwrap_or(80);
            let prog_width = term_width as u128 * (duration.as_millis() - remain.as_millis())
                / duration.as_millis();
            let prog_width = prog_width as usize;
            let message = format!("{} ({:.0?})", reason, remain);

            let mut reversed_string = String::new();
            let mut default_string = String::new();
            let mut col = 0;
            for grapheme in Graphemes::new(&message) {
                // Once we've passed the elapsed column, full up the string
                // that we'll render with default attributes instead.
                if col > prog_width {
                    default_string.push_str(grapheme);
                } else {
                    reversed_string.push_str(grapheme);
                }
                col += 1;
            }

            // If we didn't reach the elapsed column yet (really short text!),
            // we need to pad out the reversed string.
            while col < prog_width {
                reversed_string.push(' ');
                col += 1;
            }

            let combined = format!("{}{}", reversed_string, default_string);

            if last_draw.is_none() || last_draw.as_ref().unwrap() != &combined {
                self.term.render(&[
                    Change::CursorPosition {
                        x: Position::Absolute(0),
                        y: Position::Relative(0),
                    },
                    Change::AllAttributes(CellAttributes::default().set_reverse(true).clone()),
                    Change::Text(reversed_string),
                    Change::AllAttributes(CellAttributes::default()),
                    Change::Text(default_string),
                ])?;
                last_draw.replace(combined);
            }

            // We use poll_input rather than a raw sleep here so that
            // eg: resize events can be processed and reflected in the
            // dimensions reported at the top of the loop.
            // We're using a sub-second value for the delay here for a
            // slightly smoother progress bar.
            self.term
                .poll_input(Some(remain.min(Duration::from_millis(50))))?;
        }

        let message = format!("{} (done)\r\n", reason);
        self.term.render(&[
            Change::CursorPosition {
                x: Position::Absolute(0),
                y: Position::Relative(0),
            },
            Change::Text(message),
        ])?;

        Ok(())
    }
}

struct HeadlessImpl {
    rx: Receiver<UIRequest>,
}

impl HeadlessImpl {
    fn run(&mut self) -> anyhow::Result<()> {
        loop {
            match self.rx.recv_timeout(Duration::from_millis(200)) {
                Ok(UIRequest::Close) => break,
                Ok(UIRequest::Output(changes)) => {
                    log::trace!("Output: {:?}", changes);
                }
                Ok(UIRequest::Input { mut respond, .. }) => {
                    respond.result(Err(anyhow!("Input requested from headless context")));
                }
                Ok(UIRequest::Sleep {
                    mut respond,
                    reason,
                    duration,
                }) => {
                    log::error!("{} (sleeping for {:?})", reason, duration);
                    std::thread::sleep(duration);
                    respond.result(Ok(()));
                }
                Err(err) if err.is_timeout() => {}
                Err(err) => bail!("recv_timeout: {}", err),
            }
        }

        Ok(())
    }
}

/// Headless `ConnectionUI` backend that answers `Input` requests via a
/// caller-supplied responder. Used by embedded hosts to wire SSH auth
/// prompts (password, passphrase, host-verify) to existing credentials
/// without opening a terminal-overlay window.
struct ResponderImpl {
    rx: Receiver<UIRequest>,
    responder: Box<dyn Fn(&str, bool, &str) -> Option<String> + Send + 'static>,
    /// Text emitted via `UIRequest::Output` since the last `Input` prompt.
    ///
    /// Fallback context for prompts that carry no typed `context` field
    /// (e.g. keyboard-interactive instructions): without it an embedded
    /// responder would answer with no idea what the prompt refers to.
    /// Host-key verification does NOT rely on this buffer any more — its
    /// fingerprint message travels typed in `UIRequest::Input::context`, so
    /// the server-controlled banner buffered here cannot spoof it.
    pending_output: String,
}

impl ResponderImpl {
    fn run(&mut self) -> anyhow::Result<()> {
        loop {
            match self.rx.recv_timeout(Duration::from_millis(200)) {
                Ok(UIRequest::Close) => break,
                Ok(UIRequest::Output(changes)) => {
                    for change in &changes {
                        if let Change::Text(text) = change {
                            self.pending_output.push_str(text);
                        }
                    }
                    log::trace!("Output: {:?}", changes);
                }
                Ok(UIRequest::Input {
                    prompt,
                    echo,
                    context,
                    mut respond,
                }) => {
                    // Prefer the TYPED context when the caller supplied one
                    // (host-key verification passes the client-computed
                    // fingerprint message) and DISCARD the buffered output for
                    // that prompt: the buffer is untyped and may contain
                    // server-controlled text (the SSH banner arrives before
                    // verification), which could spoof an extra
                    // fingerprint-looking line above the real one. The buffer
                    // remains the fallback for prompts without typed context
                    // (e.g. keyboard-interactive instructions).
                    let buffered = std::mem::take(&mut self.pending_output);
                    let context = context.unwrap_or(buffered);
                    let answer = (self.responder)(&prompt, echo, &context);
                    match answer {
                        Some(s) => respond.result(Ok(s)),
                        None => respond.result(Err(anyhow!(
                            "Input prompt {:?} declined by embedded responder",
                            prompt
                        ))),
                    };
                }
                Ok(UIRequest::Sleep {
                    mut respond,
                    reason,
                    duration,
                }) => {
                    log::trace!("{} (sleeping for {:?})", reason, duration);
                    std::thread::sleep(duration);
                    respond.result(Ok(()));
                }
                Err(err) if err.is_timeout() => {}
                Err(err) => bail!("recv_timeout: {}", err),
            }
        }
        Ok(())
    }
}

#[derive(Default, Clone, Copy, Debug)]
pub struct ConnectionUIParams {
    pub size: TerminalSize,
    pub disable_close_delay: bool,
    pub window_id: Option<crate::WindowId>,
}

#[derive(Clone)]
pub struct ConnectionUI {
    tx: Sender<UIRequest>,
}

impl ConnectionUI {
    pub fn new() -> Self {
        Self::with_params(Default::default())
    }

    pub fn with_params(params: ConnectionUIParams) -> Self {
        let (tx, rx) = unbounded();
        promise::spawn::spawn_into_main_thread(termwiztermtab::run(
            params.size,
            params.window_id,
            move |term| {
                let mut ui = ConnectionUIImpl { term, rx };
                let status = ui.run().unwrap_or_else(|e| {
                    log::error!("while running ConnectionUI loop: {:?}", e);
                    CloseStatus::Implicit
                });

                if !params.disable_close_delay && status == CloseStatus::Implicit {
                    ui.sleep(
                        "(this window will close automatically)",
                        Duration::new(120, 0),
                    )
                    .ok();
                }
                Ok(())
            },
            None,
        ))
        .detach();
        Self { tx }
    }

    pub fn new_with_no_close_delay() -> Self {
        Self::with_params(ConnectionUIParams {
            disable_close_delay: true,
            ..Default::default()
        })
    }

    pub fn new_headless() -> Self {
        let (tx, rx) = unbounded();
        std::thread::spawn(move || {
            let mut ui = HeadlessImpl { rx };
            ui.run()
        });
        Self { tx }
    }

    /// Termob fork addition: a headless `ConnectionUI` whose `Input`
    /// prompts are answered by `responder` instead of an interactive
    /// terminal overlay. Used by embedded hosts (mobile, GUI) to feed
    /// SSH auth answers from a modal / keychain.
    ///
    /// `responder` receives `(prompt, echo, context)` and returns the answer,
    /// or `None` to fail the prompt (caller-cancelled). `echo == false`
    /// means it is a password/passphrase prompt.
    ///
    /// `context` has two sources, in order of preference:
    ///
    /// 1. **Typed** — the prompt was issued via
    ///    [`ConnectionUI::input_with_context`]. Host-key verification passes
    ///    the client-computed host/fingerprint message
    ///    (`HostVerificationEvent::message`, composed by `wezterm-ssh` from
    ///    the key the server actually offered). Server-controlled text such
    ///    as the SSH banner CANNOT mix into this value.
    /// 2. **Buffered fallback** — everything this UI emitted since the
    ///    previous prompt, for prompts without a typed context (e.g.
    ///    keyboard-interactive instructions). This is untyped and may contain
    ///    server-supplied text; a responder that shows it to a human must
    ///    present it verbatim as untrusted server output.
    ///
    /// The buffer is cleared on every prompt either way, so a banner never
    /// leaks into a later prompt's context.
    pub fn new_with_input_responder<F>(responder: F) -> Self
    where
        F: Fn(&str, bool, &str) -> Option<String> + Send + 'static,
    {
        let (tx, rx) = unbounded();
        std::thread::spawn(move || {
            let mut ui = ResponderImpl {
                rx,
                responder: Box::new(responder),
                pending_output: String::new(),
            };
            ui.run()
        });
        Self { tx }
    }

    pub fn run_and_log_error<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        F: FnOnce() -> anyhow::Result<T>,
    {
        match f() {
            Err(e) => {
                let what = format!("\r\nFailed: {:?}\r\n", e);
                log::error!("{}", what);
                self.output_str(&what);
                Err(e)
            }
            result => result,
        }
    }

    pub async fn async_run_and_log_error<T, F>(&self, f: F) -> anyhow::Result<T>
    where
        F: std::future::Future<Output = anyhow::Result<T>>,
    {
        match f.await {
            Err(e) => {
                let what = format!("\r\nFailed: {:?}\r\n", e);
                self.output_str(&what);
                Err(e)
            }
            result => result,
        }
    }

    pub fn title(&self, title: &str) {
        self.output(vec![Change::Title(title.to_string())]);
    }

    pub fn output(&self, changes: Vec<Change>) {
        self.tx.send(UIRequest::Output(changes)).ok();
    }

    pub fn output_str(&self, s: &str) {
        let s = s.replace("\n", "\r\n");
        self.output(vec![Change::Text(s)]);
    }

    /// Sleep (blocking!) for the specified duration, but updates
    /// the UI with the reason and a count down during that time.
    pub fn sleep_with_reason(&self, reason: &str, duration: Duration) -> anyhow::Result<()> {
        let mut promise = Promise::new();
        let future = promise.get_future().unwrap();

        self.tx
            .send(UIRequest::Sleep {
                reason: reason.to_string(),
                duration,
                respond: promise,
            })
            .context("send to ConnectionUI failed")?;

        block_on(future)
    }

    /// Crack a multi-line prompt into an optional preamble and the prompt
    /// text on the final line.  This is needed because the line editor
    /// is only designed for a single line prompt; a multi-line prompt
    /// messes up the cursor positioning.
    fn split_multi_line_prompt(s: &str) -> (Option<String>, String) {
        let text = s.replace("\n", "\r\n");
        let bits: Vec<&str> = text.rsplitn(2, "\r\n").collect();

        if bits.len() == 2 {
            (Some(format!("{}\r\n", bits[1])), bits[0].to_owned())
        } else {
            (None, text)
        }
    }

    pub fn input(&self, prompt: &str) -> anyhow::Result<String> {
        self.input_impl(prompt, None)
    }

    /// Like [`Self::input`], but also carries a typed `context` describing
    /// what the prompt refers to. SSH host-key verification passes the
    /// client-computed host/fingerprint message here so an embedded responder
    /// (see [`Self::new_with_input_responder`]) receives it separately from
    /// the accumulated `Output` stream — that stream also carries
    /// server-controlled text (the SSH banner, printed *before* verification),
    /// which could otherwise spoof a fingerprint-looking line. Terminal
    /// overlay and headless UIs ignore the context.
    pub fn input_with_context(&self, prompt: &str, context: &str) -> anyhow::Result<String> {
        self.input_impl(prompt, Some(context.to_string()))
    }

    fn input_impl(&self, prompt: &str, context: Option<String>) -> anyhow::Result<String> {
        let mut promise = Promise::new();
        let future = promise.get_future().unwrap();

        let (preamble, prompt) = Self::split_multi_line_prompt(prompt);
        if let Some(preamble) = preamble {
            self.output(vec![Change::Text(preamble)]);
        }

        self.tx
            .send(UIRequest::Input {
                prompt,
                echo: true,
                context,
                respond: promise,
            })
            .context("send to ConnectionUI failed")?;

        block_on(future)
    }

    pub fn password(&self, prompt: &str) -> anyhow::Result<String> {
        self.password_impl(prompt, None)
    }

    /// Like [`Self::password`], but carries a typed `context` describing where
    /// the prompt came from.
    ///
    /// Termob fork, and the reason it exists is a real hole: an embedded
    /// responder (see [`Self::new_with_input_responder`]) that auto-answers
    /// secret prompts cannot tell a locally composed one — libssh asking for
    /// the passphrase of a key file on THIS machine — from one the remote host
    /// relayed over keyboard-interactive, where the server writes the prompt
    /// text itself. Answering the second with the first's secret hands the
    /// local key passphrase to the server. Prompt-text matching cannot close
    /// that, because the text is precisely what an attacker controls; the
    /// provenance has to be carried out of band, which is what this does.
    ///
    /// Callers pass [`AUTH_ORIGIN_LOCAL`] / [`AUTH_ORIGIN_SERVER`]. Terminal
    /// overlay and headless UIs ignore the context, exactly as with
    /// [`Self::input_with_context`].
    pub fn password_with_context(&self, prompt: &str, context: &str) -> anyhow::Result<String> {
        self.password_impl(prompt, Some(context.to_string()))
    }

    fn password_impl(&self, prompt: &str, context: Option<String>) -> anyhow::Result<String> {
        let mut promise = Promise::new();
        let future = promise.get_future().unwrap();

        let (preamble, prompt) = Self::split_multi_line_prompt(prompt);
        if let Some(preamble) = preamble {
            self.output(vec![Change::Text(preamble)]);
        }

        self.tx
            .send(UIRequest::Input {
                prompt,
                echo: false,
                context,
                respond: promise,
            })
            .context("send to ConnectionUI failed")?;

        block_on(future)
    }

    pub fn close(&self) {
        self.tx.send(UIRequest::Close).ok();
    }

    pub fn test_alive(&self) -> bool {
        if !self.tx.send(UIRequest::Output(vec![])).is_ok() {
            return false;
        }
        std::thread::sleep(Duration::from_millis(50));
        self.tx.send(UIRequest::Output(vec![])).is_ok()
    }
}

lazy_static::lazy_static! {
    static ref ERROR_WINDOW: Mutex<Option<ConnectionUI>> = Mutex::new(None);
}

fn get_error_window() -> ConnectionUI {
    let mut err = ERROR_WINDOW.lock().unwrap();
    if let Some(ui) = err.as_ref().map(|ui| ui.clone()) {
        ui.output_str("\n");
        if ui.test_alive() {
            return ui;
        }
    }

    let ui = ConnectionUI::new_with_no_close_delay();
    ui.title("wezterm Configuration Error");
    err.replace(ui.clone());
    ui
}

/// If the GUI has been started, pops up a window with the supplied error
/// message framed as a configuration error.
/// If there is no GUI front end, generates a toast notification instead.
pub fn show_configuration_error_message(err: &str) {
    log::error!("Configuration Error: {}", err);
    let ui = get_error_window();

    let mut wrapped = textwrap::fill(&err, 78);
    wrapped.push_str("\n");
    ui.output_str(&wrapped);
}
