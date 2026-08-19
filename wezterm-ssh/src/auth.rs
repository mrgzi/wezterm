use crate::session::SessionEvent;
use anyhow::Context;
use smol::channel::{bounded, Sender};

/// Termob fork: the ssh-config key saying that the embedder is holding this
/// user's password, so authentication should offer it before the public keys.
///
/// A hint, not a secret: the password itself never reaches the ssh config
/// (`mux::ssh::TERMOB_PASSWORD_OPTION` is taken out of it), and the config is
/// logged in full when `wezterm_ssh_verbose` is set. Set to `yes` only where
/// the user chose PASSWORD authentication — the same field carries a key's
/// passphrase, and that must never be offered to the server as a password.
pub const TERMOB_PREFER_PASSWORD_OPTION: &str = "termob_prefer_password";

#[derive(Debug)]
pub struct AuthenticationPrompt {
    pub prompt: String,
    pub echo: bool,
}

/// Who composed an authentication prompt.
///
/// Termob fork. `SessionEvent::Authenticate` is emitted from several places
/// that look identical to a consumer, but differ in a way that matters for
/// secrets: some prompts are written by the CLIENT (libssh asking for the
/// passphrase that decrypts a key file sitting on this machine), and some are
/// relayed from the REMOTE HOST (keyboard-interactive, where the server
/// chooses the prompt text outright).
///
/// Without this distinction an embedded responder cannot safely auto-answer a
/// non-echo prompt: a hostile or compromised server can send
/// `"Enter passphrase for key:"` over keyboard-interactive and be handed the
/// local key passphrase — a secret that unlocks a LOCAL file and must never
/// reach the wire. Matching on the prompt text cannot fix that, because the
/// text is exactly what the attacker controls.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPromptOrigin {
    /// Composed on this machine (key passphrase, local pubkey callback).
    /// A secret answered here never leaves the client.
    Local,
    /// Relayed from the remote host (keyboard-interactive, password auth).
    /// Anything answered here is sent to the server.
    Server,
}

#[derive(Debug)]
pub struct AuthenticationEvent {
    pub username: String,
    pub instructions: String,
    pub prompts: Vec<AuthenticationPrompt>,
    /// Termob fork: whether this prompt was composed locally or relayed from
    /// the server. See [`AuthPromptOrigin`].
    pub origin: AuthPromptOrigin,
    pub(crate) reply: Sender<Vec<String>>,
}

impl AuthenticationEvent {
    pub async fn answer(self, answers: Vec<String>) -> anyhow::Result<()> {
        Ok(self.reply.send(answers).await?)
    }

    pub fn try_answer(self, answers: Vec<String>) -> anyhow::Result<()> {
        Ok(self.reply.try_send(answers)?)
    }
}

impl crate::sessioninner::SessionInner {
    #[cfg(feature = "ssh2")]
    fn agent_auth(&mut self, sess: &ssh2::Session, user: &str) -> anyhow::Result<bool> {
        if let Some(only) = self.config.get("identitiesonly") {
            if only == "yes" {
                log::trace!("Skipping agent auth because identitiesonly=yes");
                return Ok(false);
            }
        }

        let mut agent = sess.agent()?;
        if agent.connect().is_err() {
            // If the agent is around, we can proceed with other methods
            return Ok(false);
        }

        agent.list_identities()?;
        let identities = agent.identities()?;
        for identity in identities {
            if agent.userauth(user, &identity).is_ok() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    #[cfg(feature = "ssh2")]
    fn pubkey_auth(
        &mut self,
        sess: &ssh2::Session,
        user: &str,
        host: &str,
    ) -> anyhow::Result<bool> {
        use std::path::{Path, PathBuf};

        if let Some(files) = self.config.get("identityfile") {
            // Termob fork: `split_path_list` rather than `split_whitespace` so
            // a path containing a space survives; see its doc comment.
            for file in crate::config::split_path_list(files) {
                let pubkey: PathBuf = format!("{}.pub", file).into();
                let file = Path::new(&file);

                if !file.exists() {
                    continue;
                }

                let pubkey = if pubkey.exists() {
                    Some(pubkey.as_ref())
                } else {
                    None
                };

                // We try with no passphrase first, in case the key is unencrypted
                match sess.userauth_pubkey_file(user, pubkey, &file, None) {
                    Ok(_) => {
                        log::info!("pubkey_file immediately ok for {}", file.display());
                        return Ok(true);
                    }
                    Err(_) => {
                        // Most likely cause of error is that we need a passphrase
                        // to decrypt the key, so let's prompt the user for one.
                        let (reply, answers) = bounded(1);
                        self.tx_event
                            .try_send(SessionEvent::Authenticate(AuthenticationEvent {
                                username: "".to_string(),
                                instructions: "".to_string(),
                                prompts: vec![AuthenticationPrompt {
                                    prompt: format!(
                                        "Passphrase to decrypt {} for {}@{}:\n> ",
                                        file.display(),
                                        user,
                                        host
                                    ),
                                    echo: false,
                                }],
                                // Termob fork: ssh2: passphrase decrypts a key file on THIS machine.
                                origin: AuthPromptOrigin::Local,
                                reply,
                            }))
                            .context("sending Authenticate request to user")?;

                        let answers = smol::block_on(answers.recv())
                            .context("waiting for authentication answers from user")?;

                        if answers.is_empty() {
                            anyhow::bail!("user cancelled authentication");
                        }

                        let passphrase = &answers[0];

                        match sess.userauth_pubkey_file(user, pubkey, &file, Some(passphrase)) {
                            Ok(_) => {
                                return Ok(true);
                            }
                            Err(err) => {
                                log::warn!("pubkey auth: {:#}", err);
                            }
                        }
                    }
                }
            }
        }
        Ok(false)
    }

    #[cfg(feature = "libssh-rs")]
    pub fn authenticate_libssh(&mut self, sess: &libssh_rs::Session) -> anyhow::Result<()> {
        use std::collections::HashMap;
        let tx = self.tx_event.clone();

        // Set the callback for pubkey auth
        sess.set_auth_callback(move |prompt, echo, _verify, identity| {
            let (reply, answers) = bounded(1);
            tx.try_send(SessionEvent::Authenticate(AuthenticationEvent {
                username: "".to_string(),
                instructions: "".to_string(),
                prompts: vec![AuthenticationPrompt {
                    prompt: match identity {
                        Some(ident) => format!("{} ({}): ", prompt, ident),
                        None => prompt.to_string(),
                    },
                    echo,
                }],
                // Termob fork: libssh pubkey callback: composed locally by libssh.
                origin: AuthPromptOrigin::Local,
                reply,
            }))
            .unwrap();

            let mut answers = smol::block_on(answers.recv())
                .context("waiting for authentication answers from user")
                .unwrap();
            Ok(answers.remove(0))
        });

        use libssh_rs::{AuthMethods, AuthStatus};
        match sess.userauth_none(None)? {
            AuthStatus::Success => return Ok(()),
            _ => {}
        }

        // Termob fork: whether the embedder is holding this user's password,
        // and so whether offering it first is worth a try.
        let prefer_password = matches!(
            self.config
                .get(TERMOB_PREFER_PASSWORD_OPTION)
                .map(String::as_str),
            Some("yes")
        );
        let mut password_offered = false;

        loop {
            let auth_methods = sess.userauth_list(None)?;
            let mut status_by_method = HashMap::new();

            // Termob fork: where the embedder already has the password, offer
            // it before the public keys rather than after them.
            //
            // `userauth_public_key_auto` offers the agent's keys and then every
            // default identity file, and each offer is a round trip. Against a
            // host 150 ms away that turned authentication into about seven of
            // them — a second of a five-second connection — spent proving that
            // keys the user was not authenticating with do not work.
            //
            // ONE attempt, and a refusal falls through to the ordinary chain
            // below rather than asking again here: a user whose key would have
            // worked must still connect, which is what ordering password first
            // would otherwise have taken away. The retry that a refusal does
            // deserve happens in the PASSWORD branch, after the other methods
            // have had their turn.
            //
            // Only for a real password. The same field carries a private key's
            // passphrase (the embedder collects one secret either way), and
            // offering THAT here would send it to the server as a password —
            // so the embedder sets this option only when the user chose
            // password authentication.
            if prefer_password && !password_offered && auth_methods.contains(AuthMethods::PASSWORD) {
                password_offered = true;
                let (reply, answers) = bounded(1);
                self.tx_event
                    .try_send(SessionEvent::Authenticate(AuthenticationEvent {
                        username: "".to_string(),
                        instructions: String::new(),
                        prompts: vec![AuthenticationPrompt {
                            prompt: "Password: ".to_string(),
                            echo: false,
                        }],
                        origin: AuthPromptOrigin::Server,
                        reply,
                    }))
                    .context("sending Authenticate request to user")?;
                let mut answers = smol::block_on(answers.recv())
                    .context("waiting for authentication answers from user")?;
                if !answers.is_empty() {
                    let password = answers.remove(0);
                    match sess.userauth_password(None, Some(&password))? {
                        AuthStatus::Success => return Ok(()),
                        AuthStatus::Partial => continue,
                        status => {
                            status_by_method.insert(AuthMethods::PASSWORD, status);
                        }
                    }
                }
            }

            if auth_methods.contains(AuthMethods::PUBLIC_KEY) {
                match sess.userauth_public_key_auto(None, None)? {
                    AuthStatus::Success => return Ok(()),
                    AuthStatus::Partial => continue,
                    status => {
                        status_by_method.insert(AuthMethods::PUBLIC_KEY, status);
                    }
                }
            }

            if auth_methods.contains(AuthMethods::INTERACTIVE) {
                loop {
                    match sess.userauth_keyboard_interactive(None, None)? {
                        AuthStatus::Success => return Ok(()),
                        AuthStatus::Info => {
                            let info = sess.userauth_keyboard_interactive_info()?;

                            let (reply, answers) = bounded(1);
                            self.tx_event
                                .try_send(SessionEvent::Authenticate(AuthenticationEvent {
                                    username: sess.get_user_name()?,
                                    instructions: info.instruction,
                                    prompts: info
                                        .prompts
                                        .into_iter()
                                        .map(|p| AuthenticationPrompt {
                                            prompt: p.prompt,
                                            echo: p.echo,
                                        })
                                        .collect(),
                                    // Termob fork: libssh keyboard-interactive: prompt text is the SERVER's.
                                    origin: AuthPromptOrigin::Server,
                                    reply,
                                }))
                                .context("sending Authenticate request to user")?;

                            let answers = smol::block_on(answers.recv())
                                .context("waiting for authentication answers from user")?;

                            sess.userauth_keyboard_interactive_set_answers(&answers)?;

                            continue;
                        }
                        AuthStatus::Denied => {
                            break;
                        }
                        AuthStatus::Partial => continue,
                        status => {
                            anyhow::bail!("interactive auth status: {:?}", status);
                        }
                    }
                }
            }

            if auth_methods.contains(AuthMethods::PASSWORD) {
                let (reply, answers) = bounded(1);
                self.tx_event
                    .try_send(SessionEvent::Authenticate(AuthenticationEvent {
                        username: "".to_string(),
                        instructions: "".to_string(),
                        prompts: vec![AuthenticationPrompt {
                            prompt: "Password: ".to_string(),
                            echo: false,
                        }],
                        // Termob fork: ssh2 password auth: answer is sent to the server.
                        origin: AuthPromptOrigin::Server,
                        reply,
                    }))
                    .unwrap();

                let mut answers = smol::block_on(answers.recv())
                    .context("waiting for authentication answers from user")
                    .unwrap();
                let pw = answers.remove(0);

                match sess.userauth_password(None, Some(&pw))? {
                    AuthStatus::Success => return Ok(()),
                    AuthStatus::Partial => continue,
                    status => anyhow::bail!("password auth status: {:?}", status),
                }
            }

            anyhow::bail!(
                "unhandled auth case; methods={:?}, status={:?}",
                auth_methods,
                status_by_method
            );
        }
    }

    #[cfg(feature = "ssh2")]
    pub fn authenticate(
        &mut self,
        sess: &ssh2::Session,
        user: &str,
        host: &str,
    ) -> anyhow::Result<()> {
        use std::collections::HashSet;

        loop {
            if sess.authenticated() {
                return Ok(());
            }

            // Re-query the auth methods on each loop as a successful method
            // may unlock a new method on a subsequent iteration (eg: password
            // auth may then unlock 2fac)
            let methods: HashSet<&str> = sess.auth_methods(&user)?.split(',').collect();
            log::trace!("ssh auth methods: {:?}", methods);

            if !sess.authenticated() && methods.contains("publickey") {
                if self.agent_auth(sess, user)? {
                    continue;
                }

                if self.pubkey_auth(sess, user, host)? {
                    continue;
                }
            }

            if !sess.authenticated() && methods.contains("password") {
                let (reply, answers) = bounded(1);
                self.tx_event
                    .try_send(SessionEvent::Authenticate(AuthenticationEvent {
                        username: user.to_string(),
                        instructions: "".to_string(),
                        prompts: vec![AuthenticationPrompt {
                            prompt: format!("Password for {}@{}: ", user, host),
                            echo: false,
                        }],
                        // Termob fork: libssh password auth: answer is sent to the server.
                        origin: AuthPromptOrigin::Server,
                        reply,
                    }))
                    .context("sending Authenticate request to user")?;

                let answers = smol::block_on(answers.recv())
                    .context("waiting for authentication answers from user")?;

                if answers.is_empty() {
                    anyhow::bail!("user cancelled authentication");
                }

                if let Err(err) = sess.userauth_password(user, &answers[0]) {
                    log::error!("while attempting password auth: {}", err);
                }
            }

            if !sess.authenticated() && methods.contains("keyboard-interactive") {
                struct Helper<'a> {
                    tx_event: &'a Sender<SessionEvent>,
                }

                impl<'a> ssh2::KeyboardInteractivePrompt for Helper<'a> {
                    fn prompt<'b>(
                        &mut self,
                        username: &str,
                        instructions: &str,
                        prompts: &[ssh2::Prompt<'b>],
                    ) -> Vec<String> {
                        let (reply, answers) = bounded(1);
                        if let Err(err) = self.tx_event.try_send(SessionEvent::Authenticate(
                            AuthenticationEvent {
                                username: username.to_string(),
                                instructions: instructions.to_string(),
                                prompts: prompts
                                    .iter()
                                    .map(|p| AuthenticationPrompt {
                                        prompt: p.text.to_string(),
                                        echo: p.echo,
                                    })
                                    .collect(),
                                // Termob fork: ssh2 keyboard-interactive: prompt text is the SERVER's.
                                origin: AuthPromptOrigin::Server,
                                reply,
                            },
                        )) {
                            log::error!("sending Authenticate request to user: {:#}", err);
                            return vec![];
                        }

                        match smol::block_on(answers.recv()) {
                            Err(err) => {
                                log::error!(
                                    "waiting for authentication answers from user: {:#}",
                                    err
                                );
                                return vec![];
                            }
                            Ok(answers) => answers,
                        }
                    }
                }

                let mut helper = Helper {
                    tx_event: &self.tx_event,
                };

                if let Err(err) = sess.userauth_keyboard_interactive(user, &mut helper) {
                    log::error!("while attempting keyboard-interactive auth: {}", err);
                }
            }
        }
    }
}
