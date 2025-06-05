use cert_checker::core::get_certificate_info;
use chrono::{Duration, Utc};
use rustls::Certificate;
use x509_parser::prelude::*;

fn create_test_certificate(not_before: chrono::DateTime<Utc>, not_after: chrono::DateTime<Utc>) -> Certificate {
    // Format dates in ASN.1 GeneralizedTime format (YYYYMMDDHHMMSSZ)
    let format_date = |dt: chrono::DateTime<Utc>| {
        dt.format("%Y%m%d%H%M%SZ").to_string().into_bytes()
    };
    
    let not_before_bytes = format_date(not_before);
    let not_after_bytes = format_date(not_after);
    
    // Calculate lengths
    let validity_len = 2 + not_before_bytes.len() + 2 + not_after_bytes.len();
    let total_len = 4 + 3 + 10 + 15 + 11 + validity_len + 11 + 42 + 5 + 15 + 33;
    
    // Create a minimal valid X.509 certificate structure
    let mut cert_der = vec![
        // SEQUENCE
        0x30, (total_len >> 8) as u8, (total_len & 0xFF) as u8,
        // Version
        0xA0, 0x03, 0x02, 0x01, 0x02,
        // Serial Number
        0x02, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        // Signature Algorithm
        0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
        // Issuer
        0x30, 0x0B, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x00,
        // Validity
        0x30, validity_len as u8,
        // Not Before
        0x17, not_before_bytes.len() as u8,
    ];
    
    // Add not_before date
    cert_der.extend_from_slice(&not_before_bytes);
    
    // Add not_after date
    cert_der.extend_from_slice(&[0x17, not_after_bytes.len() as u8]);
    cert_der.extend_from_slice(&not_after_bytes);
    
    // Continue with the rest of the certificate
    cert_der.extend_from_slice(&[
        // Subject
        0x30, 0x0B, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x00,
        // Subject Public Key Info
        0x30, 0x2A,
        // Algorithm
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        // Public Key
        0x03, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        // Extensions
        0xA3, 0x03, 0x02, 0x01, 0x02,
        // Signature
        0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B, 0x05, 0x00,
        0x03, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
    ]);
    
    // Debug: Print certificate structure
    println!("Certificate structure:");
    println!("  Total length: {}", cert_der.len());
    println!("  Expected length: {}", total_len);
    println!("  Not before: {}", String::from_utf8_lossy(&not_before_bytes));
    println!("  Not after: {}", String::from_utf8_lossy(&not_after_bytes));
    
    // Try to parse the certificate
    match X509Certificate::from_der(&cert_der) {
        Ok((_, cert)) => {
            println!("Certificate parsed successfully:");
            println!("  Version: {}", cert.version());
            println!("  Serial: {:?}", cert.serial);
            println!("  Validity: {:?}", cert.validity());
        }
        Err(e) => {
            println!("Certificate parsing failed: {}", e);
            println!("Certificate DER: {:?}", cert_der);
            panic!("Invalid certificate structure: {}", e);
        }
    }
    
    Certificate(cert_der)
}

#[test]
fn test_certificate_info_valid() {
    let now = Utc::now();
    let not_before = now - Duration::days(30);
    let not_after = now + Duration::days(30);
    
    let cert = create_test_certificate(not_before, not_after);
    let info = get_certificate_info(&cert).unwrap();
    
    println!("Valid certificate test:");
    println!("  Not before: {}", not_before);
    println!("  Not after: {}", not_after);
    println!("  Is valid: {}", info.is_valid);
    println!("  Is expired: {}", info.is_expired);
    println!("  Is not yet valid: {}", info.is_not_yet_valid);
    println!("  Days until expiry: {}", info.days_until_expiry);
    
    assert!(info.is_valid);
    assert!(!info.is_expired);
    assert!(!info.is_not_yet_valid);
    assert!(info.days_until_expiry > 0);
}

#[test]
fn test_certificate_info_expired() {
    let now = Utc::now();
    let not_before = now - Duration::days(60);
    let not_after = now - Duration::days(30);
    
    let cert = create_test_certificate(not_before, not_after);
    let info = get_certificate_info(&cert).unwrap();
    
    println!("Expired certificate test:");
    println!("  Not before: {}", not_before);
    println!("  Not after: {}", not_after);
    println!("  Is valid: {}", info.is_valid);
    println!("  Is expired: {}", info.is_expired);
    println!("  Is not yet valid: {}", info.is_not_yet_valid);
    println!("  Days until expiry: {}", info.days_until_expiry);
    
    assert!(!info.is_valid);
    assert!(info.is_expired);
    assert!(!info.is_not_yet_valid);
    assert!(info.days_until_expiry < 0);
}

#[test]
fn test_certificate_info_not_yet_valid() {
    let now = Utc::now();
    let not_before = now + Duration::days(30);
    let not_after = now + Duration::days(60);
    
    let cert = create_test_certificate(not_before, not_after);
    let info = get_certificate_info(&cert).unwrap();
    
    println!("Not yet valid certificate test:");
    println!("  Not before: {}", not_before);
    println!("  Not after: {}", not_after);
    println!("  Is valid: {}", info.is_valid);
    println!("  Is expired: {}", info.is_expired);
    println!("  Is not yet valid: {}", info.is_not_yet_valid);
    println!("  Days until expiry: {}", info.days_until_expiry);
    
    assert!(!info.is_valid);
    assert!(!info.is_expired);
    assert!(info.is_not_yet_valid);
    assert!(info.days_until_expiry > 0);
}

#[test]
fn test_warning_threshold() {
    let now = Utc::now();
    let not_before = now - Duration::days(30);
    let not_after = now + Duration::days(15); // Less than default warning threshold
    
    let cert = create_test_certificate(not_before, not_after);
    let info = get_certificate_info(&cert).unwrap();
    
    println!("Warning threshold test:");
    println!("  Not before: {}", not_before);
    println!("  Not after: {}", not_after);
    println!("  Is valid: {}", info.is_valid);
    println!("  Is expired: {}", info.is_expired);
    println!("  Is not yet valid: {}", info.is_not_yet_valid);
    println!("  Days until expiry: {}", info.days_until_expiry);
    
    assert!(info.is_valid);
    assert!(!info.is_expired);
    assert!(!info.is_not_yet_valid);
    assert!(info.days_until_expiry <= 30); // Should be less than default warning threshold
} 