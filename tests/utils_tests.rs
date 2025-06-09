use cert_checker::types::{CertificateInfo, CertificateChain};
use cert_checker::utils::display_certificate_info;
use chrono::{Utc, Duration};

fn create_cert(valid_from: chrono::DateTime<chrono::Utc>, valid_until: chrono::DateTime<chrono::Utc>) -> CertificateInfo {
    let now = Utc::now();
    let is_expired = now > valid_until;
    let is_not_yet_valid = now < valid_from;
    let is_valid = !is_expired && !is_not_yet_valid;
    let days_until_expiry = (valid_until - now).num_days();
    CertificateInfo {
        valid_from,
        valid_until,
        issuer: "Test Issuer".to_string(),
        subject: "Test Subject".to_string(),
        serial_number: "123456789".to_string(),
        signature_algorithm: "SHA256".to_string(),
        is_valid,
        is_expired,
        is_not_yet_valid,
        days_until_expiry,
        certificate_type: "server".to_string(),
    }
}

fn create_test_cert_chain() -> CertificateChain {
    let now = Utc::now();
    let cert_info = create_cert(now - Duration::days(30), now + Duration::days(60));
    CertificateChain {
        certificates: vec![cert_info],
        is_chain_valid: true,
    }
}

#[test]
fn test_display_text_format() {
    let chain = create_test_cert_chain();
    let result = display_certificate_info(&chain, "text", 30);
    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("Certificate Chain"));
    assert!(output.contains("Valid"));
}

#[test]
fn test_display_json_format() {
    let chain = create_test_cert_chain();
    let result = display_certificate_info(&chain, "json", 30);
    assert!(result.is_ok());
    let output = result.unwrap();
    println!("JSON output: {}", output);
    assert!(output.contains("\"is_valid\": true"));
    assert!(output.contains("\"status\": \"valid\""), "output was: {}", output);
}

#[test]
fn test_display_invalid_format() {
    let chain = create_test_cert_chain();
    let result = display_certificate_info(&chain, "invalid", 30);
    // Should fall back to text format and return Ok
    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("Certificate Chain"));
}

#[test]
fn test_display_warning_days() {
    let now = Utc::now();
    let cert_info = create_cert(now - Duration::days(10), now + Duration::days(10)); // Expires in 10 days
    let chain = CertificateChain {
        certificates: vec![cert_info],
        is_chain_valid: true,
    };
    let result = display_certificate_info(&chain, "text", 15);
    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("Warning"));
}

#[test]
fn test_display_expired_certificate() {
    let now = Utc::now();
    let cert_info = create_cert(now - Duration::days(30), now - Duration::days(1)); // Expired
    let chain = CertificateChain {
        certificates: vec![cert_info],
        is_chain_valid: false,
    };
    let result = display_certificate_info(&chain, "text", 30);
    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("Expired"));
}

#[test]
fn test_display_not_yet_valid_certificate() {
    let now = Utc::now();
    let cert_info = create_cert(now + Duration::days(1), now + Duration::days(30)); // Not yet valid
    let chain = CertificateChain {
        certificates: vec![cert_info],
        is_chain_valid: false,
    };
    let result = display_certificate_info(&chain, "text", 30);
    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("Not Yet Valid"));
}

#[test]
fn test_display_chain_validation() {
    let mut chain = create_test_cert_chain();
    chain.is_chain_valid = false;
    let result = display_certificate_info(&chain, "text", 30);
    assert!(result.is_ok());
    let output = result.unwrap();
    assert!(output.contains("Invalid"));
}

#[test]
fn test_display_certificate_info_multiple_certs() {
    let now = Utc::now();
    let mut chain = create_test_cert_chain();
    // Add an intermediate certificate
    let intermediate = create_cert(now - Duration::days(60), now + Duration::days(60));
    chain.certificates.push(intermediate);
    let result = display_certificate_info(&chain, "text", 30);
    assert!(result.is_ok());
} 