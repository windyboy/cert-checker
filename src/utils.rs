use anyhow::Result;
use serde_json::json;
use tracing::debug;
use crate::core::CertificateChain;

pub fn display_certificate_info(chain: &CertificateChain, warning_days: u32, format: &str) -> Result<()> {
    match format {
        "json" => {
            debug!("Outputting certificate chain information in JSON format");
            let json_output = json!({
                "is_chain_valid": chain.is_chain_valid,
                "certificates": chain.certificates.iter().map(|cert| {
                    json!({
                        "type": cert.certificate_type,
                        "valid_from": cert.valid_from.to_rfc3339(),
                        "valid_until": cert.valid_until.to_rfc3339(),
                        "issuer": cert.issuer,
                        "subject": cert.subject,
                        "serial_number": cert.serial_number,
                        "signature_algorithm": cert.signature_algorithm,
                        "is_valid": cert.is_valid,
                        "is_expired": cert.is_expired,
                        "is_not_yet_valid": cert.is_not_yet_valid,
                        "days_until_expiry": cert.days_until_expiry,
                        "warning": if cert.days_until_expiry <= warning_days as i64 {
                            format!("Certificate will expire in {} days", cert.days_until_expiry)
                        } else {
                            String::new()
                        }
                    })
                }).collect::<Vec<_>>()
            });
            println!("{}", serde_json::to_string_pretty(&json_output)?);
        }
        _ => {
            debug!("Outputting certificate chain information in text format");
            
            // Print chain status with a separator line
            println!("\n{}", "=".repeat(80));
            println!("Certificate Chain Status: {}", 
                if chain.is_chain_valid { 
                    "✓ Valid".to_string() 
                } else { 
                    "⚠️ Invalid".to_string() 
                }
            );
            println!("{}", "=".repeat(80));
            
            // Print each certificate with clear separation
            for (i, cert) in chain.certificates.iter().enumerate() {
                println!("\n{}", "-".repeat(80));
                println!("Certificate #{} ({})", i + 1, cert.certificate_type.to_uppercase());
                println!("{}", "-".repeat(80));
                
                // Basic Information
                println!("\nBasic Information:");
                println!("  Subject: {}", cert.subject);
                println!("  Issuer:  {}", cert.issuer);
                
                // Validity Period
                println!("\nValidity Period:");
                println!("  Valid From:  {}", cert.valid_from);
                println!("  Valid Until: {}", cert.valid_until);
                
                // Technical Details
                println!("\nTechnical Details:");
                println!("  Serial Number:        {}", cert.serial_number);
                println!("  Signature Algorithm:  {}", cert.signature_algorithm);
                
                // Status Information
                println!("\nStatus Information:");
                if cert.is_expired {
                    println!("  ⚠️  Certificate is EXPIRED");
                } else if cert.is_not_yet_valid {
                    println!("  ⚠️  Certificate is NOT YET VALID");
                } else {
                    println!("  ✓ Certificate is VALID");
                    if cert.days_until_expiry <= warning_days as i64 {
                        println!("  ⚠️  Warning: Will expire in {} days", cert.days_until_expiry);
                    } else {
                        println!("  ✓ Days until expiry: {}", cert.days_until_expiry);
                    }
                }
            }
            
            // Print final separator
            println!("\n{}", "=".repeat(80));
        }
    }
    
    Ok(())
} 