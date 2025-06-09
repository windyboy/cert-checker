use crate::types::{CertificateChain, CertificateInfo};
use crate::core::{is_certificate_expiring_soon, validate_certificate_chain};
use chrono::Utc;
use serde_json::json;
use thiserror::Error;
use std::fmt::Write;
use colored::*;

#[derive(Error, Debug)]
pub enum UtilsError {
    #[error("JSON serialization error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Display certificate information in the specified format
///
/// # Arguments
///
/// * `chain` - The certificate chain to display
/// * `format` - The output format ("text" or "json")
/// * `warning_days` - Number of days before expiration to show warning
///
/// # Returns
///
/// A `Result` containing the formatted string or an error
///
/// # Examples
///
/// ```
/// use cert_checker::types::CertificateChain;
/// use cert_checker::utils::display_certificate_info;
///
/// let chain = CertificateChain {
///     certificates: vec![],
///     is_chain_valid: true,
/// };
/// display_certificate_info(&chain, "text", 30)?;
/// Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn display_certificate_info(chain: &CertificateChain, format: &str, warning_days: u32) -> Result<String, UtilsError> {
    match format {
        "text" => display_text(chain, warning_days),
        "json" => display_json(chain, warning_days),
        _ => display_text(chain, warning_days), // Default to text format
    }
}

/// Display certificate information in text format
pub fn display_text(chain: &CertificateChain, warning_days: u32) -> Result<String, UtilsError> {
    let mut output = String::new();
    
    // Header
    writeln!(output, "{}", "🔒 Certificate Chain Analysis".cyan().bold()).unwrap();
    writeln!(output, "{}", "=".repeat(50).cyan()).unwrap();

    for (i, cert) in chain.certificates.iter().enumerate() {
        // Certificate header
        writeln!(output, "\n{}", format!("📜 Certificate {} ({})", i + 1, cert.certificate_type).cyan()).unwrap();
        writeln!(output, "{}", "-".repeat(50).cyan()).unwrap();
        
        // Basic info
        writeln!(output, "{}", "Subject:".bold()).unwrap();
        writeln!(output, "  {}", cert.subject).unwrap();
        writeln!(output, "{}", "Issuer:".bold()).unwrap();
        writeln!(output, "  {}", cert.issuer).unwrap();
        
        // Validity period
        writeln!(output, "\n{}", "Validity Period:".bold()).unwrap();
        writeln!(output, "  From: {}", cert.valid_from.format("%Y-%m-%d %H:%M:%S UTC")).unwrap();
        writeln!(output, "  To:   {}", cert.valid_until.format("%Y-%m-%d %H:%M:%S UTC")).unwrap();
        
        // Additional details
        writeln!(output, "\n{}", "Details:".bold()).unwrap();
        writeln!(output, "  Serial Number: {}", cert.serial_number).unwrap();
        writeln!(output, "  Signature Algorithm: {}", cert.signature_algorithm).unwrap();
        
        // Status
        writeln!(output, "\n{}", "Status:".bold()).unwrap();
        writeln!(output, "  {}", get_status_text(cert, warning_days)).unwrap();
    }

    // Chain status
    writeln!(output, "\n{}", "=".repeat(50).cyan()).unwrap();
    writeln!(output, "{}", format!("🔗 Chain Status: {}", 
        if chain.is_chain_valid { "✅ Valid".green() } else { "❌ Invalid".red() }).cyan()).unwrap();
    writeln!(output, "{}", "=".repeat(50).cyan()).unwrap();

    Ok(output)
}

/// Display certificate information in JSON format
pub fn display_json(chain: &CertificateChain, warning_days: u32) -> Result<String, UtilsError> {
    let mut certificates = Vec::new();
    
    for cert in &chain.certificates {
        let status = if !cert.is_valid {
            if cert.is_expired {
                "expired"
            } else if cert.is_not_yet_valid {
                "not_yet_valid"
            } else {
                "invalid"
            }
        } else {
            let days_remaining = (cert.valid_until - Utc::now()).num_days();
            if days_remaining <= warning_days as i64 {
                "warning"
            } else {
                "valid"
            }
        };

        certificates.push(json!({
            "type": cert.certificate_type,
            "subject": cert.subject,
            "issuer": cert.issuer,
            "valid_from": cert.valid_from.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            "valid_until": cert.valid_until.format("%Y-%m-%d %H:%M:%S UTC").to_string(),
            "serial_number": cert.serial_number,
            "signature_algorithm": cert.signature_algorithm,
            "status": status,
            "days_remaining": (cert.valid_until - Utc::now()).num_days()
        }));
    }

    let output = json!({
        "certificate_chain": {
            "is_valid": chain.is_chain_valid,
            "certificates": certificates
        }
    });

    Ok(serde_json::to_string_pretty(&output)?)
}

/// Get a human-readable status text for a certificate
pub fn get_status_text(cert: &CertificateInfo, warning_days: u32) -> String {
    if !cert.is_valid {
        if cert.is_expired {
            "❌ Expired".red().to_string()
        } else if cert.is_not_yet_valid {
            "⏳ Not Yet Valid".yellow().to_string()
        } else {
            "❌ Invalid".red().to_string()
        }
    } else {
        let days_remaining = (cert.valid_until - Utc::now()).num_days();
        if days_remaining <= warning_days as i64 {
            format!("⚠️  Warning: Expires in {} days", days_remaining).yellow().to_string()
        } else {
            "✅ Valid".green().to_string()
        }
    }
}

/// # Examples
///
/// ```
/// use cert_checker::types::CertificateInfo;
/// use cert_checker::utils::display_expiry_warning;
/// use chrono::{Utc, Duration};
///
/// let now = Utc::now();
/// let cert = CertificateInfo {
///     valid_from: now - Duration::days(30),
///     valid_until: now + Duration::days(10),
///     issuer: "Test Issuer".to_string(),
///     subject: "Test Subject".to_string(),
///     serial_number: "123456789".to_string(),
///     signature_algorithm: "SHA256".to_string(),
///     is_valid: true,
///     is_expired: false,
///     is_not_yet_valid: false,
///     days_until_expiry: 10,
///     certificate_type: "server".to_string(),
/// };
/// let warning = display_expiry_warning(&cert, 15);
/// assert!(warning.contains("Warning"));
/// ```
#[allow(dead_code)]
pub fn display_expiry_warning(cert: &CertificateInfo, warning_days: u32) -> String {
    if is_certificate_expiring_soon(cert, warning_days) {
        format!("⚠️  Warning: Certificate for {} expires in {} days.", cert.subject, cert.days_until_expiry)
    } else {
        String::new()
    }
}

/// # Examples
///
/// ```
/// use cert_checker::types::{CertificateChain, CertificateInfo};
/// use cert_checker::utils::display_chain_validation_status;
/// use chrono::{Utc, Duration};
///
/// let now = Utc::now();
/// let cert1 = CertificateInfo {
///     valid_from: now - Duration::days(30),
///     valid_until: now + Duration::days(30),
///     issuer: "Test Issuer".to_string(),
///     subject: "Test Subject".to_string(),
///     serial_number: "123456789".to_string(),
///     signature_algorithm: "SHA256".to_string(),
///     is_valid: true,
///     is_expired: false,
///     is_not_yet_valid: false,
///     days_until_expiry: 30,
///     certificate_type: "server".to_string(),
/// };
/// let cert2 = CertificateInfo {
///     valid_from: now - Duration::days(60),
///     valid_until: now + Duration::days(60),
///     issuer: "Root CA".to_string(),
///     subject: "Intermediate CA".to_string(),
///     serial_number: "987654321".to_string(),
///     signature_algorithm: "SHA256".to_string(),
///     is_valid: true,
///     is_expired: false,
///     is_not_yet_valid: false,
///     days_until_expiry: 60,
///     certificate_type: "intermediate".to_string(),
/// };
/// let chain = CertificateChain {
///     certificates: vec![cert1, cert2],
///     is_chain_valid: true,
/// };
/// let status = display_chain_validation_status(&chain);
/// assert!(status.contains("valid"));
/// ```
#[allow(dead_code)]
pub fn display_chain_validation_status(chain: &CertificateChain) -> String {
    if validate_certificate_chain(&chain.certificates) {
        "✅ Certificate chain is valid.".to_string()
    } else {
        "❌ Certificate chain is invalid.".to_string()
    }
} 