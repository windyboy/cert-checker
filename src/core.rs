use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rustls::{Certificate, RootCertStore};
use std::{path::Path, sync::Arc};
use tokio::net::TcpStream;
use url::Url;
use x509_parser::prelude::*;

#[derive(Debug)]
pub struct CertificateInfo {
    pub valid_from: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub issuer: String,
    pub subject: String,
    pub serial_number: String,
    pub signature_algorithm: String,
    pub is_valid: bool,
    pub is_expired: bool,
    pub is_not_yet_valid: bool,
    pub days_until_expiry: i64,
    pub certificate_type: String, // "server", "intermediate", or "root"
}

#[derive(Debug)]
pub struct CertificateChain {
    pub certificates: Vec<CertificateInfo>,
    pub is_chain_valid: bool,
}

pub async fn check_certificate(url: &str, cert_store: Option<&Path>) -> Result<CertificateChain> {
    // Add https:// scheme if no scheme is provided
    let url_str = if !url.contains("://") {
        format!("https://{}", url)
    } else {
        url.to_string()
    };

    // Parse the URL
    let url = Url::parse(&url_str)
        .context("Failed to parse URL")?;

    if url.scheme() == "http" {
        anyhow::bail!("HTTP does not use TLS, cannot retrieve certificate");
    }
    
    // Ensure we have a host
    let host = url.host_str()
        .context("URL must have a host")?;
    
    // Use port 80 for HTTP and 443 for HTTPS
    let port = url.port().unwrap_or_else(|| {
        match url.scheme() {
            "http" => 80,
            "https" => 443,
            _ => 443, // Default to HTTPS port for unknown schemes
        }
    });
    
    // Create a new TCP connection
    let addr = format!("{}:{}", host, port);
    let stream = TcpStream::connect(&addr)
        .await
        .context("Failed to connect to server")?;
    
    // Set up TLS configuration
    let mut root_store = RootCertStore::empty();
    if let Some(dir) = cert_store {
        for entry in std::fs::read_dir(dir)
            .with_context(|| format!("Failed to read cert store at {}", dir.display()))?
        {
            let entry = entry?;
            if entry.file_type()?.is_file() {
                let path = entry.path();
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext.eq_ignore_ascii_case("pem") || ext.eq_ignore_ascii_case("crt") {
                    let data = std::fs::read(&path)
                        .with_context(|| format!("Failed to read certificate {}", path.display()))?;
                    let mut cursor = &data[..];
                    for cert in rustls_pemfile::certs(&mut cursor)? {
                        root_store.add(&Certificate(cert))?;
                    }
                }
            }
        }
    } else {
        for cert in rustls_native_certs::load_native_certs()? {
            root_store.add(&Certificate(cert.as_ref().to_vec()))?;
        }
    }
    
    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    let config = Arc::new(config);
    
    // Create TLS connector
    let connector = tokio_rustls::TlsConnector::from(config);
    
    // Perform TLS handshake
    let domain = rustls::ServerName::try_from(host)
        .context("Invalid server name")?;
    let stream = connector.connect(domain, stream)
        .await
        .context("Failed to establish TLS connection")?;
    
    // Get all peer certificates
    let certs = stream.get_ref().1.peer_certificates()
        .context("Failed to get peer certificates")?;
    
    let mut chain = CertificateChain {
        certificates: Vec::new(),
        is_chain_valid: true,
    };

    // Process each certificate in the chain
    for (i, cert) in certs.iter().enumerate() {
        let mut info = get_certificate_info(cert)?;
        
        // Determine certificate type
        info.certificate_type = if i == 0 {
            "server".to_string()
        } else if i == certs.len() - 1 {
            "root".to_string()
        } else {
            "intermediate".to_string()
        };

        // Update chain validity
        if !info.is_valid {
            chain.is_chain_valid = false;
        }

        chain.certificates.push(info);
    }

    Ok(chain)
}

pub fn get_certificate_info(cert: &Certificate) -> Result<CertificateInfo> {
    let cert_der = cert.as_ref();
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate: {}", e))?;
    
    let not_before = DateTime::<Utc>::from_timestamp(
        cert.tbs_certificate.validity.not_before.timestamp() as i64,
        0,
    )
    .ok_or_else(|| anyhow::anyhow!("Invalid certificate timestamp"))?;

    let not_after = DateTime::<Utc>::from_timestamp(
        cert.tbs_certificate.validity.not_after.timestamp() as i64,
        0,
    )
    .ok_or_else(|| anyhow::anyhow!("Invalid certificate timestamp"))?;
    
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
        certificate_type: String::new(), // Will be set by the caller
    })
} 