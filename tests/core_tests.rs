use cert_checker::core::get_certificate_info;
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

#[test]
fn test_url_scheme_handling() {
    use cert_checker::core::check_certificate;
    use tokio::runtime::Runtime;

    let rt = Runtime::new().unwrap();
    
    // Test cases for different URL formats using a non-existent domain
    let test_cases = vec![
        ("https://this-domain-does-not-exist.example", 443),
        ("http://this-domain-does-not-exist.example", 80),
        ("https://this-domain-does-not-exist.example", 443), // Default to HTTPS
        ("https://this-domain-does-not-exist.example:8443", 8443),
        ("http://this-domain-does-not-exist.example:8080", 8080),
    ];

    for (url, _expected_port) in test_cases {
        rt.block_on(async {
            // We expect these to fail with connection errors since we're using a non-existent domain
            let result = check_certificate(url).await;
            match result {
                Ok(_) => {
                    // If we get here, it means the connection succeeded, which shouldn't happen
                    // since we're using a non-existent domain
                    panic!("Unexpected successful connection for URL: {}", url);
                }
                Err(e) => {
                    let err_str = e.to_string();
                    // Verify that we got a connection error
                    assert!(
                        err_str.contains("Failed to connect to server"),
                        "Expected connection error for URL {}, got: {}",
                        url,
                        err_str
                    );
                }
            }
        });
    }
} 