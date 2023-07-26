//! TLS tooling.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// The default path to OpenShift's Service CA certificate.
pub const SERVICE_CA_CERT: &str = "/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt";

/// A client configuration.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientConfig {
    #[serde(default)]
    pub tls_insecure: bool,
    #[serde(default)]
    pub ca_certificates: Vec<String>,
    /// A second way to provide a single certificate, works with the config crate, which
    /// doesn't properly support lists.
    #[serde(default)]
    pub ca_certificate: Option<String>,
}

impl ClientConfig {
    pub fn certificates(&self) -> impl Iterator<Item = &str> {
        let service_ca = {
            let cert = Path::new(SERVICE_CA_CERT);
            if cert.exists() {
                log::info!("Adding Service CA certificate ({:?})", cert);
                Some(SERVICE_CA_CERT)
            } else {
                None
            }
        };

        self.ca_certificates
            .iter()
            .map(|s| s.as_str())
            .chain(self.ca_certificate.iter().map(|s| s.as_str()))
            .chain(service_ca.into_iter())
    }
}

impl TryFrom<&ClientConfig> for native_tls::TlsConnector {
    type Error = anyhow::Error;

    fn try_from(config: &ClientConfig) -> Result<Self, Self::Error> {
        use anyhow::Context;

        let mut tls = native_tls::TlsConnector::builder();

        if config.tls_insecure {
            log::warn!("Disabling TLS verification for client. Do not use this in production!");
            tls.danger_accept_invalid_certs(true);
            tls.danger_accept_invalid_hostnames(true);
        }

        for cert in config.certificates() {
            let cert = std::fs::read(cert).context("Reading certificate")?;
            let cert = native_tls::Certificate::from_pem(&cert)?;
            tls.add_root_certificate(cert);
        }

        tls.build().context("Create TLS connector")
    }
}
