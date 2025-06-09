use cert_checker::core::{parse_certificate};
use chrono::{Duration, Utc, Datelike};
use rustls::Certificate;
use rcgen::{CertificateParams, Certificate as RcgenCertificate, date_time_ymd};

fn create_test_certificate(not_before: chrono::DateTime<Utc>, not_after: chrono::DateTime<Utc>) -> Certificate {
    let mut params = CertificateParams::default();
    params.not_before = date_time_ymd(
        not_before.year(),
        not_before.month() as u8,
        not_before.day() as u8,
    );
    params.not_after = date_time_ymd(
        not_after.year(),
        not_after.month() as u8,
        not_after.day() as u8,
    );
    let cert = RcgenCertificate::from_params(params).unwrap();
    Certificate(cert.serialize_der().unwrap())
}

#[test]
fn test_certificate_info_valid() {
    let now = Utc::now();
    let not_before = now - Duration::days(30);
    let not_after = now + Duration::days(30);
    
    let cert = create_test_certificate(not_before, not_after);
    let info = parse_certificate(&cert, true).unwrap();
    
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
    let info = parse_certificate(&cert, true).unwrap();
    
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
    let info = parse_certificate(&cert, true).unwrap();
    
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
    let info = parse_certificate(&cert, true).unwrap();
    
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

#[test]
fn test_certificate_info_edge_cases() {
    // Test certificate with same start and end date
    let now = Utc::now();
    let cert = create_test_certificate(now, now);
    let info = parse_certificate(&cert, true).unwrap();
    assert_eq!(info.valid_until, info.valid_from);
    assert!(!info.is_valid);
    assert!(info.is_expired);
    assert!(!info.is_not_yet_valid);
    assert_eq!(info.days_until_expiry, 0);

    // Test certificate with very long validity period
    // Add a day buffer to account for time-of-day truncation
    let not_before = now - Duration::days(365 * 10) - Duration::days(1); // 10 years ago, minus 1 day
    let not_after = now + Duration::days(365 * 10) + Duration::days(1);  // 10 years from now, plus 1 day
    let cert = create_test_certificate(not_before, not_after);
    let info = parse_certificate(&cert, true).unwrap();
    println!("[DEBUG] not_before: {} not_after: {}", not_before, not_after);
    println!("[DEBUG] valid_from: {} valid_until: {}", info.valid_from, info.valid_until);
    
    // Check that the validity period is at least 3650 days
    assert!(info.valid_until >= info.valid_from);
    assert!((info.valid_until - info.valid_from).num_days() >= 3650);
    
    // Check that the certificate is valid by checking the validity flags
    assert!(info.is_valid);
    assert!(!info.is_expired);
    assert!(!info.is_not_yet_valid);
    assert!(info.days_until_expiry > 0);

    // Test certificate with very short validity period
    // Add a day buffer to account for time-of-day truncation
    let not_before = now - Duration::days(1); // 1 day ago
    let not_after = now + Duration::days(1);  // 1 day from now
    let cert = create_test_certificate(not_before, not_after);
    let info = parse_certificate(&cert, true).unwrap();
    println!("[DEBUG] short valid_from: {} valid_until: {}", info.valid_from, info.valid_until);
    
    // For short validity period, check the validity flags
    assert!(info.valid_until >= info.valid_from);
    assert!(info.is_valid);
    assert!(!info.is_expired);
    assert!(!info.is_not_yet_valid);
    assert!(info.days_until_expiry < 2); // Less than 2 days
}

#[test]
fn test_certificate_info_invalid_dates() {
    // Test certificate with end date before start date
    let now = Utc::now();
    let not_before = now + Duration::days(30);
    let not_after = now - Duration::days(30);
    let cert = create_test_certificate(not_before, not_after);
    let info = parse_certificate(&cert, true).unwrap();
    assert!(!info.is_valid);
    assert!(info.is_expired);
    assert!(info.is_not_yet_valid); // This should be true since not_before is in the future
    assert!(info.days_until_expiry < 0);
} 