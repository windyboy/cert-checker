use crate::error::CertCheckerError;
use crate::types::{CertificateChain, CertificateInfo};
use chrono::{DateTime, Utc};
use std::sync::Arc;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::{ClientConfig, ServerName, Certificate};
use tracing::{debug, error};
use x509_parser::prelude::*;
use rustls::client::{ServerCertVerified, ServerCertVerifier};
use std::time::SystemTime;

// --- BEGIN: NoVerifier for development only ---
struct NoVerifier;
impl ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        // TODO: Use a real verifier in production!
        Ok(ServerCertVerified::assertion())
    }
}
// --- END: NoVerifier ---

#[allow(dead_code)]
/// Custom error types for certificate checking operations
pub enum CertError {
    /// Failed to parse URL
    UrlParseError(String),
    /// Failed to connect
    ConnectionError(String),
    /// Failed to parse certificate
    ParseError(String),
}

/// Check a single certificate
pub async fn check_certificate(url: &str, warning_days: u32, concurrent: usize) -> Result<CertificateChain, CertCheckerError> {
    debug!("Checking certificate for {}", url);
    let _warning_days = warning_days; // silence unused variable warning
    
    // Create a semaphore to limit concurrent connections
    let semaphore = if concurrent > 1 {
        Some(Arc::new(Semaphore::new(concurrent))) // Limit to 'concurrent' connections
    } else {
        None
    };

    // Acquire permit if using concurrent mode
    let _permit = if let Some(sem) = &semaphore {
        Some(sem.acquire().await.map_err(|e| {
            error!("Failed to acquire semaphore: {}", e);
            CertCheckerError::ConnectionError("Failed to acquire connection permit".to_string())
        })?)
    } else {
        None
    };

    // Set a timeout for the connection
    let timeout_duration = std::time::Duration::from_secs(10);
    
    // Connect to the server and get the certificate chain
    let chain = timeout(timeout_duration, async {
        let config = ClientConfig::builder()
            .with_safe_defaults()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));

        let stream = tokio::net::TcpStream::connect(format!("{}:443", url))
            .await
            .map_err(|e| {
                error!("Failed to connect to {}: {}", url, e);
                CertCheckerError::ConnectionError(format!("Failed to connect to {}: {}", url, e))
            })?;

        let domain = ServerName::try_from(url)
            .map_err(|e| {
                error!("Invalid server name {}: {}", url, e);
                CertCheckerError::ConnectionError(format!("Invalid server name {}: {}", url, e))
            })?;

        let _stream = connector
            .connect(domain, stream)
            .await
            .map_err(|e| {
                error!("Failed to establish TLS connection to {}: {}", url, e);
                CertCheckerError::ConnectionError(format!("Failed to establish TLS connection to {}: {}", url, e))
            })?;

        // TODO: Extract peer certificates from the TLS stream.
        // The following is a placeholder. You must implement extraction of the certificate chain from the stream.
        let certs: Vec<Certificate> = Vec::new();

        let mut certificates = Vec::new();
        for (i, cert) in certs.iter().enumerate() {
            let cert_info = parse_certificate(cert, i == 0)?;
            certificates.push(cert_info);
        }
        let is_chain_valid = validate_certificate_chain(&certificates);
        Ok::<_, CertCheckerError>(CertificateChain {
            certificates,
            is_chain_valid,
        })
    })
    .await
    .map_err(|e| {
        error!("Connection timeout for {}: {}", url, e);
        CertCheckerError::ConnectionError(format!("Connection timeout for {}: {}", url, e))
    })??;

    Ok(chain)
}

/// Parse a certificate and return its information
pub fn parse_certificate(cert: &Certificate, is_server: bool) -> Result<CertificateInfo, CertCheckerError> {
    let cert_der = cert.as_ref();
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| CertCheckerError::ParseError(e.to_string()))?;
    
    let not_before = DateTime::<Utc>::from_timestamp(
        cert.tbs_certificate.validity.not_before.timestamp() as i64,
        0,
    ).unwrap_or_default();
    
    let not_after = DateTime::<Utc>::from_timestamp(
        cert.tbs_certificate.validity.not_after.timestamp() as i64,
        0,
    ).unwrap_or_default();
    
    let now = Utc::now();
    let is_expired = now > not_after;
    let is_not_yet_valid = now < not_before;
    let is_valid = !is_expired && !is_not_yet_valid;
    let days_until_expiry = (not_after - now).num_days();
    
    Ok(CertificateInfo {
        valid_from: not_before,
        valid_until: not_after,
        issuer: cert.tbs_certificate.issuer.to_string(),
        subject: cert.tbs_certificate.subject.to_string(),
        serial_number: cert.tbs_certificate.serial.to_string(),
        signature_algorithm: cert.signature_algorithm.algorithm.to_string(),
        is_valid,
        is_expired,
        is_not_yet_valid,
        days_until_expiry,
        certificate_type: if is_server { "server".to_string() } else { "intermediate".to_string() },
    })
}

/// Check if a certificate is expiring soon
pub fn is_certificate_expiring_soon(cert: &CertificateInfo, warning_days: u32) -> bool {
    let now = Utc::now();
    let days_until_expiry = (cert.valid_until - now).num_days();
    days_until_expiry >= 0 && days_until_expiry <= warning_days as i64
}

/// Validate a certificate chain
pub fn validate_certificate_chain(chain: &[CertificateInfo]) -> bool {
    if chain.is_empty() {
        return false;
    }
    for i in 0..chain.len() - 1 {
        if !chain[i].is_valid || !chain[i + 1].is_valid {
            return false;
        }
    }
    true
}