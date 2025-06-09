use thiserror::Error;

#[derive(Error, Debug)]
pub enum CertCheckerError {
    #[error("Connection error: {0}")]
    ConnectionError(String),
    #[error("No certificates found for {0}")]
    NoCertificatesFound(String),
    #[error("Parse error: {0}")]
    ParseError(String),
} 