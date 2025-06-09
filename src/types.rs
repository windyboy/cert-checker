use chrono::{DateTime, Utc};

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
    pub certificate_type: String,
}

#[derive(Debug)]
pub struct CertificateChain {
    pub certificates: Vec<CertificateInfo>,
    pub is_chain_valid: bool,
} 