//! An abstraction over a terminal device

use crate::caps::probed::ProbeCapabilities;
use crate::caps::Capabilities;
use crate::input::InputEvent;
use crate::surface::Change;
use crate::{format_err, Result};
#[cfg(all(unix, any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
use crate::bail;
use num_traits::NumCast;
use std::fmt::Display;
use std::time::Duration;

#[cfg(feature = "use_serde")]
use serde::Deserialize;
#[cfg(feature = "use_serde")]
use serde::Serialize;

// `unix` module pulls in the `termios` crate which lacks Apple-mobile
// `target_os` cfg branches; gate it off iOS/tvOS/watchOS/visionOS.
// Mobile consumers don't run on a real TTY so the UnixTerminal driver
// is never instantiated there anyway.
#[cfg(all(unix, not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))))]
pub mod unix;
#[cfg(windows)]
pub mod windows;

pub mod buffered;

#[cfg(all(unix, not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))))]
pub use self::unix::{UnixTerminal, UnixTerminalWaker as TerminalWaker};
#[cfg(windows)]
pub use self::windows::{WindowsTerminal, WindowsTerminalWaker as TerminalWaker};

// On Apple mobile targets the UnixTerminal driver is gated off (no
// termios support there), so there's no concrete waker type to alias.
// Keep the public `TerminalWaker` symbol available as a stub so that
// the `Terminal` trait and downstream callers like `lineedit` still
// type-check. Constructing one isn't supported — code paths that need
// a real waker only run on the gated-out UnixTerminal.
#[cfg(all(unix, any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
#[derive(Clone)]
pub struct TerminalWaker;

#[cfg(all(unix, any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
impl TerminalWaker {
    /// Stub: waking is unsupported on Apple mobile targets where there
    /// is no UnixTerminal to wake.
    pub fn wake(&self) -> std::io::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "TerminalWaker is unavailable on Apple mobile targets",
        ))
    }
}

/// Represents the size of the terminal screen.
/// The number of rows and columns of character cells are expressed.
/// Some implementations populate the size of those cells in pixels.
// On Windows, GetConsoleFontSize() can return the size of a cell in
// logical units and we can probably use this to populate xpixel, ypixel.
// GetConsoleScreenBufferInfo() can return the rows and cols.
#[cfg_attr(feature = "use_serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScreenSize {
    /// The number of rows of text
    pub rows: usize,
    /// The number of columns per row
    pub cols: usize,
    /// The width of a cell in pixels.  Some implementations never
    /// set this to anything other than zero.
    pub xpixel: usize,
    /// The height of a cell in pixels.  Some implementations never
    /// set this to anything other than zero.
    pub ypixel: usize,
}

#[cfg_attr(feature = "use_serde", derive(Serialize, Deserialize))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blocking {
    DoNotWait,
    Wait,
}

/// `Terminal` abstracts over some basic terminal capabilities.
/// If the `set_raw_mode` or `set_cooked_mode` functions are used in
/// any combination, the implementation is required to restore the
/// terminal mode that was in effect when it was created.
pub trait Terminal {
    /// Raw mode disables input line buffering, allowing data to be
    /// read as the user presses keys, disables local echo, so keys
    /// pressed by the user do not implicitly render to the terminal
    /// output, and disables canonicalization of unix newlines to CRLF.
    fn set_raw_mode(&mut self) -> Result<()>;
    fn set_cooked_mode(&mut self) -> Result<()>;

    /// Enter the alternate screen.  The alternate screen will be left
    /// automatically when the `Terminal` is dropped.
    fn enter_alternate_screen(&mut self) -> Result<()>;

    /// Exit the alternate screen.
    fn exit_alternate_screen(&mut self) -> Result<()>;

    /// Queries the current screen size, returning width, height.
    fn get_screen_size(&mut self) -> Result<ScreenSize>;

    /// Returns a capability probing helper that will use escape
    /// sequences to attempt to probe information from the terminal
    fn probe_capabilities(&mut self) -> Option<ProbeCapabilities<'_>> {
        None
    }

    /// Sets the current screen size
    fn set_screen_size(&mut self, size: ScreenSize) -> Result<()>;

    /// Render a series of changes to the terminal output
    fn render(&mut self, changes: &[Change]) -> Result<()>;

    /// Flush any buffered output
    fn flush(&mut self) -> Result<()>;

    /// Check for a parsed input event.
    /// `wait` indicates the behavior in the case that no input is
    /// immediately available.  If wait is `None` then `poll_input`
    /// will not return until an event is available.  If wait is
    /// `Some(duration)` then `poll_input` will wait up to the given
    /// duration for an event before returning with a value of
    /// `Ok(None)`.  If wait is `Some(Duration::ZERO)` then the
    /// poll is non-blocking.
    ///
    /// The possible values returned as `InputEvent`s depend on the
    /// mode of the terminal.  Most values are not returned unless
    /// the terminal is set to raw mode.
    fn poll_input(&mut self, wait: Option<Duration>) -> Result<Option<InputEvent>>;

    fn waker(&self) -> TerminalWaker;
}

/// `SystemTerminal` is a concrete implementation of `Terminal`.
/// Ideally you wouldn't reference `SystemTerminal` in consuming
/// code.  This type is exposed for convenience if you are doing
/// something unusual and want easier access to the constructors.
#[cfg(all(unix, not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos"))))]
pub type SystemTerminal = UnixTerminal;
#[cfg(windows)]
pub type SystemTerminal = WindowsTerminal;

/// Construct a new instance of Terminal.
/// The terminal will have a renderer that is influenced by the configuration
/// in the provided `Capabilities` instance.
/// The terminal will explicitly open `/dev/tty` on Unix systems and
/// `CONIN$` and `CONOUT$` on Windows systems, so that it should yield a
/// functioning console with minimal headaches.
/// If you have a more advanced use case you will want to look to the
/// constructors for `UnixTerminal` and `WindowsTerminal` and call whichever
/// one is most suitable for your needs.
#[cfg(any(windows, all(unix, not(any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))))]
pub fn new_terminal(caps: Capabilities) -> Result<impl Terminal> {
    SystemTerminal::new(caps)
}

// Apple mobile targets have no UnixTerminal driver (termios crate
// lacks the cfg branch). Provide a never-succeeding stub so that
// callers like `lineedit::line_editor_terminal` still type-check on
// these targets — they're not expected to be invoked at runtime.
#[cfg(all(unix, any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
pub fn new_terminal(_caps: Capabilities) -> Result<MobileStubTerminal> {
    bail!("new_terminal is unavailable on Apple mobile targets");
}

/// Uninhabited terminal placeholder for Apple mobile targets where the
/// real `UnixTerminal` cannot be built.
#[cfg(all(unix, any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
pub enum MobileStubTerminal {}

#[cfg(all(unix, any(target_os = "ios", target_os = "tvos", target_os = "watchos", target_os = "visionos")))]
impl Terminal for MobileStubTerminal {
    fn set_raw_mode(&mut self) -> Result<()> { match *self {} }
    fn set_cooked_mode(&mut self) -> Result<()> { match *self {} }
    fn enter_alternate_screen(&mut self) -> Result<()> { match *self {} }
    fn exit_alternate_screen(&mut self) -> Result<()> { match *self {} }
    fn get_screen_size(&mut self) -> Result<ScreenSize> { match *self {} }
    fn set_screen_size(&mut self, _size: ScreenSize) -> Result<()> { match *self {} }
    fn render(&mut self, _changes: &[Change]) -> Result<()> { match *self {} }
    fn flush(&mut self) -> Result<()> { match *self {} }
    fn poll_input(&mut self, _wait: Option<Duration>) -> Result<Option<InputEvent>> { match *self {} }
    fn waker(&self) -> TerminalWaker { match *self {} }
}

pub(crate) fn cast<T: NumCast + Display + Copy, U: NumCast>(n: T) -> Result<U> {
    num_traits::cast(n).ok_or_else(|| format_err!("{} is out of bounds for this system", n))
}
