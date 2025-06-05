use anyhow::Result;
use serde_json::json;
use tracing::{debug, info, warn};
use crate::core::CertificateInfo;

pub fn display_certificate_info(info: &CertificateInfo, warning_days: u32, format: &str) -> Result<()> {
    match format {
        "json" => {
            debug!("Outputting certificate information in JSON format");
            let json_output = json!({
                "valid_from": info.valid_from.to_rfc3339(),
                "valid_until": info.valid_until.to_rfc3339(),
                "issuer": info.issuer,
                "subject": info.subject,
                "serial_number": info.serial_number,
                "signature_algorithm": info.signature_algorithm,
                "is_valid": info.is_valid,
                "is_expired": info.is_expired,
                "is_not_yet_valid": info.is_not_yet_valid,
                "days_until_expiry": info.days_until_expiry,
                "warning": if info.days_until_expiry <= warning_days as i64 {
                    format!("Certificate will expire in {} days", info.days_until_expiry)
                } else {
                    String::new()
                }
            });
            println!("{}", serde_json::to_string_pretty(&json_output)?);
        }
        _ => {
            debug!("Outputting certificate information in text format");
            println!("\nCertificate Information:");
            println!("Valid from: {}", info.valid_from);
            println!("Valid until: {}", info.valid_until);
            println!("Issuer: {}", info.issuer);
            println!("Subject: {}", info.subject);
            println!("Serial Number: {}", info.serial_number);
            println!("Signature Algorithm: {}", info.signature_algorithm);
            
            if info.is_expired {
                warn!("Certificate is expired");
                println!("⚠️  Certificate is expired!");
            } else if info.is_not_yet_valid {
                warn!("Certificate is not yet valid");
                println!("⚠️  Certificate is not yet valid!");
            } else {
                info!("Certificate is valid");
                println!("✓ Certificate is valid");
                if info.days_until_expiry <= warning_days as i64 {
                    warn!("Certificate will expire in {} days", info.days_until_expiry);
                    println!("⚠️  Warning: Certificate will expire in {} days", info.days_until_expiry);
                }
            }
        }
    }
    
    Ok(())
} 