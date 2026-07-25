use anyhow::{anyhow, Context as _};
#[cfg(unix)]
use libc::{AF_UNSPEC, AI_CANONNAME, SOCK_DGRAM};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
};
use std::path::PathBuf;
#[cfg(windows)]
use winapi::shared::ws2def::{AF_UNSPEC, AI_CANONNAME, SOCK_DGRAM};

/// A helper for managing keys for the TLS server component.
///
/// Termob fork: the CA is generated once and then *persisted* (certificate
/// AND private key) in the pki dir. Upstream regenerated the CA on every
/// server start, which invalidated every previously distributed
/// ca.pem/client.pem the moment the server restarted — clients then failed
/// with "certificate verify failed" until the credentials were copied over
/// again. Reusing the persisted CA keeps previously issued client
/// credentials valid across restarts. Delete the pki dir to force a fresh
/// CA (revoking all prior credentials).
///
/// The idea is that the client connects via some other secure
/// channel (eg: ssh to reach the host, then unix domain to access
/// the server) to make a request for the key information.
/// We'll generate that request a new client cert and return
/// both the public CA certificate information and that key to the client.
/// The client will use both of those things to connect to the TLS
/// server.
pub struct Pki {
    ca_cert: Certificate,
    /// The exact PEM bytes served to clients. When the CA was loaded from
    /// disk these are the original bytes, NOT a re-serialization — clients
    /// that already hold a copy must keep matching byte-for-byte.
    ca_pem_data: String,
    pki_dir: PathBuf,
}

impl Pki {
    pub fn init() -> anyhow::Result<Self> {
        let pki_dir = config::pki_dir()?;
        std::fs::create_dir_all(&pki_dir)?;
        log::debug!("pki dir is {}", pki_dir.display());

        let ca_pem_path = pki_dir.join("ca.pem");
        let ca_key_path = pki_dir.join("ca-key.pem");
        let server_pem_path = pki_dir.join("server.pem");

        if ca_pem_path.exists() && ca_key_path.exists() && server_pem_path.exists() {
            match Self::load_existing(&pki_dir) {
                Ok(pki) => {
                    log::debug!("reusing persisted CA from {}", pki_dir.display());
                    return Ok(pki);
                }
                Err(err) => {
                    log::warn!(
                        "failed to load persisted CA from {} ({err:#}); \
                         generating a fresh one (previously issued client \
                         credentials will stop working)",
                        pki_dir.display()
                    );
                }
            }
        }

        let alt_names = Self::compute_alt_names()?;
        log::debug!("generating cert with alt_names={alt_names:?}");

        // Create the CA certificate
        let mut ca_params = CertificateParams::new(alt_names.clone());
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(1));
        ca_params.serial_number = Some(0.into());
        let ca_cert = Certificate::from_params(ca_params)?;
        let ca_pem = ca_cert.serialize_pem()?;
        write_atomic(&ca_pem_path, ca_pem.as_bytes(), false)
            .context(format!("saving {}", ca_pem_path.display()))?;

        // Persist the CA private key so the CA can be reused after a
        // restart. Without the key the CA cannot sign new client certs.
        let ca_key_pem = ca_cert.get_key_pair().serialize_pem();
        write_atomic(&ca_key_path, ca_key_pem.as_bytes(), true)
            .context(format!("saving {}", ca_key_path.display()))?;

        Self::issue_server_cert(&ca_cert, alt_names, &server_pem_path)?;

        Ok(Self {
            pki_dir,
            ca_cert,
            ca_pem_data: ca_pem,
        })
    }

    /// Reload a previously persisted CA (cert + private key) so that
    /// credentials issued before a server restart keep validating.
    ///
    /// The server LEAF cert is re-issued from the persisted CA on every
    /// load with freshly computed alt names: the leaf carries the
    /// hostname/IP SANs, and reusing a stale leaf would resurrect the
    /// "connect by new IP fails hostname verification" problem the IP SANs
    /// exist to solve. Clients validate the chain against ca.pem, so a new
    /// leaf under the same CA stays valid for previously distributed creds.
    fn load_existing(pki_dir: &std::path::Path) -> anyhow::Result<Self> {
        let ca_pem_path = pki_dir.join("ca.pem");
        let ca_key_path = pki_dir.join("ca-key.pem");
        let server_pem_path = pki_dir.join("server.pem");

        let ca_pem_data = std::fs::read_to_string(&ca_pem_path)
            .context(format!("reading {}", ca_pem_path.display()))?;
        let ca_key_pem = std::fs::read_to_string(&ca_key_path)
            .context(format!("reading {}", ca_key_path.display()))?;

        let key_pair = KeyPair::from_pem(&ca_key_pem).context("parsing persisted CA key")?;
        let params = CertificateParams::from_ca_cert_pem(&ca_pem_data, key_pair)
            .context("parsing persisted CA certificate")?;
        let ca_cert = Certificate::from_params(params)
            .context("reconstructing CA from persisted params")?;

        let alt_names = Self::compute_alt_names()?;
        Self::issue_server_cert(&ca_cert, alt_names, &server_pem_path)?;

        Ok(Self {
            pki_dir: pki_dir.to_path_buf(),
            ca_cert,
            ca_pem_data,
        })
    }

    /// Issue (or re-issue) the server leaf cert+key pem, signed by `ca_cert`,
    /// with the given subject alt names. The file contains the private key,
    /// so it is written atomically with owner-only permissions.
    fn issue_server_cert(
        ca_cert: &Certificate,
        alt_names: Vec<String>,
        server_pem_path: &std::path::Path,
    ) -> anyhow::Result<()> {
        let unix_name = config::username_from_env()?;
        let mut params = CertificateParams::new(alt_names);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, unix_name);
        params.distinguished_name = dn;

        let server_cert = Certificate::from_params(params)?;
        let mut signed_cert = server_cert.serialize_pem_with_signer(ca_cert)?;
        let key_bits = server_cert.get_key_pair().serialize_pem();
        signed_cert.push_str(&key_bits);

        write_atomic(server_pem_path, signed_cert.as_bytes(), true)
            .context(format!("saving {}", server_pem_path.display()))
    }

    /// Subject alt names for the server certificate: hostname, localhost,
    /// canonical DNS names, and the host's resolved IP addresses.
    ///
    /// Termob fork: the IP addresses are new. Clients frequently connect by
    /// LAN/tailnet IP rather than hostname; without an IP SAN, hostname
    /// verification always failed for such connections and users had to
    /// disable hostname checking entirely. `CertificateParams::new` turns
    /// any entry that parses as an IP into a proper IpAddress SAN.
    fn compute_alt_names() -> anyhow::Result<Vec<String>> {
        let hostname = hostname::get()?
            .into_string()
            .map_err(|_| anyhow!("hostname is not representable as unicode"))?;

        let mut alt_names = vec![
            hostname.clone(),
            "localhost".to_owned(),
            "127.0.0.1".to_owned(),
            "::1".to_owned(),
        ];

        let hints = dns_lookup::AddrInfoHints {
            flags: AI_CANONNAME,
            address: AF_UNSPEC,
            socktype: SOCK_DGRAM,
            protocol: 0,
        };

        if let Ok(iter) = dns_lookup::getaddrinfo(Some(&hostname), None, Some(hints)) {
            for entry in iter.flatten() {
                if let Some(canon) = entry.canonname {
                    alt_names.push(canon);
                }
                alt_names.push(entry.sockaddr.ip().to_string());
            }
        }

        alt_names.sort();
        alt_names.dedup();
        Ok(alt_names)
    }

    pub fn generate_client_cert(&self) -> anyhow::Result<String> {
        let unix_name = config::username_from_env()?;

        let mut params = CertificateParams::new(vec![unix_name.clone()]);
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, unix_name);
        params.distinguished_name = dn;

        let client_cert = Certificate::from_params(params)?;
        let mut signed_cert = client_cert.serialize_pem_with_signer(&self.ca_cert)?;
        let key_bits = client_cert.get_key_pair().serialize_pem();
        signed_cert.push_str(&key_bits);

        Ok(signed_cert)
    }

    pub fn ca_pem_string(&self) -> anyhow::Result<String> {
        Ok(self.ca_pem_data.clone())
    }

    pub fn ca_pem(&self) -> PathBuf {
        self.pki_dir.join("ca.pem")
    }

    pub fn server_pem(&self) -> PathBuf {
        self.pki_dir.join("server.pem")
    }
}

/// Write a PEM file atomically (temp file + rename) so a concurrently
/// starting second server or an in-flight reader never observes a
/// half-written file. `private` additionally restricts the file to
/// owner-only on unix (for files that carry a private key).
///
/// Public so that embedders which issue their own credentials next to this
/// PKI (a client cert re-issued when the CA rotated, for example) write them
/// under the same guarantees instead of reaching for `std::fs::write`, which
/// is neither atomic nor owner-only.
pub fn write_atomic(path: &std::path::Path, bytes: &[u8], private: bool) -> anyhow::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| anyhow!("{} has no parent dir", path.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("pki-file"),
        std::process::id()
    ));
    std::fs::write(&tmp, bytes)?;
    if private {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))?;
        }
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}
