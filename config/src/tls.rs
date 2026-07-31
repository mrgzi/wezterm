use crate::config::validate_domain_name;
use crate::*;
use wezterm_dynamic::{FromDynamic, ToDynamic};

#[derive(Default, Debug, Clone, FromDynamic, ToDynamic)]
pub struct TlsDomainServer {
    /// The address:port combination on which the server will listen
    /// for client connections
    pub bind_address: String,

    /// the path to an x509 PEM encoded private key file
    pub pem_private_key: Option<PathBuf>,

    /// the path to an x509 PEM encoded certificate file
    pub pem_cert: Option<PathBuf>,

    /// the path to an x509 PEM encoded CA chain file
    pub pem_ca: Option<PathBuf>,

    /// A set of paths to load additional CA certificates.
    /// Each entry can be either the path to a directory
    /// or to a PEM encoded CA file.  If an entry is a directory,
    /// then its contents will be loaded as CA certs and added
    /// to the trust store.
    #[dynamic(default)]
    pub pem_root_certs: Vec<PathBuf>,
}

#[derive(Default, Debug, Clone, FromDynamic, ToDynamic)]
pub struct TlsDomainClient {
    /// The name of this specific domain.  Must be unique amongst
    /// all types of domain in the configuration file.
    #[dynamic(validate = "validate_domain_name")]
    pub name: String,

    /// If set, use ssh to connect, start the server, and obtain
    /// a certificate.
    /// The value is "user@host:port", just like "wezterm ssh" accepts.
    pub bootstrap_via_ssh: Option<String>,

    /// ssh_config option values for the one-shot bootstrap ssh session,
    /// mirroring `SshDomain::ssh_option`.
    ///
    /// Without this there is no way to tell the bootstrap session which
    /// identity to use: it is built from `Config::new()` +
    /// `add_default_config_files()`, so it can only ever see `~/.ssh/config`
    /// and the default `~/.ssh/id_*` search. On a platform where neither
    /// exists -- an Android or iOS app sandbox, where `$HOME` is the app's
    /// own data directory and there is no ssh-agent -- the bootstrap can
    /// therefore never authenticate, which makes `bootstrap_via_ssh`
    /// unusable in exactly the place it is most useful.
    ///
    /// The values are caller-trusted, the same contract as
    /// `SshDomain::ssh_option`. Leaving this empty (the default) reproduces
    /// the previous behaviour byte for byte.
    #[dynamic(default)]
    pub ssh_option: HashMap<String, String>,

    /// identifies the host:port pair of the remote server.
    pub remote_address: String,

    /// the path to an x509 PEM encoded private key file
    pub pem_private_key: Option<PathBuf>,

    /// the path to an x509 PEM encoded certificate file
    pub pem_cert: Option<PathBuf>,

    /// the path to an x509 PEM encoded CA chain file
    pub pem_ca: Option<PathBuf>,

    /// A set of paths to load additional CA certificates.
    /// Each entry can be either the path to a directory or to a PEM encoded
    /// CA file.  If an entry is a directory, then its contents will be
    /// loaded as CA certs and added to the trust store.
    #[dynamic(default)]
    pub pem_root_certs: Vec<PathBuf>,

    /// explicitly control whether the client checks that the certificate
    /// presented by the server matches the hostname portion of
    /// `remote_address`.  The default is true.  This option is made
    /// available for troubleshooting purposes and should not be used outside
    /// of a controlled environment as it weakens the security of the TLS
    /// channel.
    #[dynamic(default)]
    pub accept_invalid_hostnames: bool,

    /// the hostname string that we expect to match against the common name
    /// field in the certificate presented by the server.  This defaults to
    /// the hostname portion of the `remote_address` configuration and you
    /// should not normally need to override this value.
    pub expected_cn: Option<String>,

    /// If true, connect to this domain automatically at startup
    #[dynamic(default)]
    pub connect_automatically: bool,

    #[dynamic(default = "default_read_timeout")]
    pub read_timeout: Duration,

    #[dynamic(default = "default_write_timeout")]
    pub write_timeout: Duration,

    /// How long to wait for the TCP handshake before giving up on an address.
    ///
    /// Termob fork; `read_timeout`/`write_timeout` only start applying once a
    /// connection exists, so without this a filtered port hangs for the OS
    /// SYN-retry budget. See [`default_connect_timeout`].
    #[dynamic(default = "default_connect_timeout")]
    pub connect_timeout: Duration,

    #[dynamic(default = "default_local_echo_threshold_ms")]
    pub local_echo_threshold_ms: Option<u64>,

    /// The path to the wezterm binary on the remote host
    pub remote_wezterm_path: Option<String>,

    /// Show time since last response when waiting for a response.
    /// It is recommended to use
    /// <https://wezterm.org/config/lua/pane/get_metadata.html#since_last_response_ms>
    /// instead.
    #[dynamic(default)]
    pub overlay_lag_indicator: bool,
}

impl TlsDomainClient {
    pub fn ssh_parameters(&self) -> Option<anyhow::Result<SshParameters>> {
        self.bootstrap_via_ssh
            .as_ref()
            .map(|user_at_host_and_port| user_at_host_and_port.parse())
    }
}
