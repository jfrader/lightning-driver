use super::*;
use rustls::{
    client::{verify_server_name, ServerCertVerified, ServerCertVerifier},
    server::ParsedCertificate,
    Certificate, CertificateError, ClientConfig, ServerName,
};
use std::{sync::Arc, time::SystemTime};

// Pinning replaces chain trust, not subject-name or handshake-signature verification.
// The default ServerCertVerifier signature methods still prove possession of the key.
struct PinnedCertificate(Certificate);

impl ServerCertVerifier for PinnedCertificate {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp: &[u8],
        now: SystemTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if end_entity != &self.0 {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::UnknownIssuer,
            ));
        }
        let (_, cert) = x509_parser::parse_x509_certificate(&end_entity.0)
            .map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadEncoding))?;
        let seconds = now
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .and_then(|v| i64::try_from(v.as_secs()).ok())
            .ok_or(rustls::Error::FailedToGetCurrentTime)?;
        if seconds < cert.validity().not_before.timestamp() {
            return Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidYet,
            ));
        }
        if seconds > cert.validity().not_after.timestamp() {
            return Err(rustls::Error::InvalidCertificate(CertificateError::Expired));
        }
        verify_server_name(&ParsedCertificate::try_from(end_entity)?, server_name)?;
        Ok(ServerCertVerified::assertion())
    }
}

pub(super) fn pinned_config(pem: &[u8]) -> Result<ClientConfig> {
    let certificates = rustls_pemfile::certs(&mut std::io::Cursor::new(pem))
        .map_err(|_| failure(ErrorCode::NotConfigured))?;
    let [der] = certificates.as_slice() else {
        return Err(failure(ErrorCode::NotConfigured));
    };
    let certificate = Certificate(der.clone());
    ParsedCertificate::try_from(&certificate).map_err(|_| failure(ErrorCode::NotConfigured))?;
    Ok(ClientConfig::builder()
        .with_safe_defaults()
        .with_custom_certificate_verifier(Arc::new(PinnedCertificate(certificate)))
        .with_no_client_auth())
}

#[derive(Clone)]
pub(super) struct Connector {
    pub config: Arc<ClientConfig>,
    pub host: String,
    pub port: u16,
    pub name: ServerName,
}

impl tonic::codegen::Service<tonic::codegen::http::Uri> for Connector {
    type Response = tokio_rustls::client::TlsStream<tokio::net::TcpStream>;
    type Error = std::io::Error;
    type Future = std::pin::Pin<Box<dyn Future<Output = std::io::Result<Self::Response>> + Send>>;

    fn poll_ready(
        &mut self,
        _: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: tonic::codegen::http::Uri) -> Self::Future {
        let this = self.clone();
        Box::pin(async move {
            let stream = tokio::net::TcpStream::connect((this.host.as_str(), this.port)).await?;
            tokio_rustls::TlsConnector::from(this.config)
                .connect(this.name, stream)
                .await
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn pinned_verifier_enforces_validity_period() {
        let cert = Certificate(
            include_bytes!("../../../tests/fixtures/cln-v25.02/synthetic-cert.der").to_vec(),
        );
        let (_, parsed) = x509_parser::parse_x509_certificate(&cert.0).unwrap();
        let before = parsed.validity().not_before.timestamp() as u64;
        let after = parsed.validity().not_after.timestamp() as u64;
        let verifier = PinnedCertificate(cert.clone());
        let name = ServerName::try_from("localhost").unwrap();
        for (seconds, expected) in [
            (before - 1, Some(CertificateError::NotValidYet)),
            (before + 1, None),
            (after + 1, Some(CertificateError::Expired)),
        ] {
            let result = verifier.verify_server_cert(
                &cert,
                &[],
                &name,
                &mut std::iter::empty(),
                &[],
                SystemTime::UNIX_EPOCH + Duration::from_secs(seconds),
            );
            match expected {
                Some(error) => {
                    assert_eq!(result.err(), Some(rustls::Error::InvalidCertificate(error)))
                }
                None => assert!(result.is_ok()),
            }
        }
    }

    #[test]
    fn pinned_config_requires_one_well_formed_certificate() {
        let pem = include_bytes!("../../../tests/fixtures/cln-v25.02/synthetic-ca.pem");
        assert!(pinned_config(pem).is_ok());
        for invalid in [
            vec![],
            b"not a certificate".to_vec(),
            [pem.as_slice(), pem.as_slice()].concat(),
            b"-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----".to_vec(),
        ] {
            assert_eq!(
                pinned_config(&invalid).err().unwrap().code,
                ErrorCode::NotConfigured
            );
        }
    }
}
