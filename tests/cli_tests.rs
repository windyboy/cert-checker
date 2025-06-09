use cert_checker::cli::Args;
use clap::Parser;

#[test]
fn test_parse_args_minimal() {
    let args = Args::try_parse_from(["cert-checker", "example.com"]).unwrap();
    assert_eq!(args.urls, vec!["example.com"]);
    assert_eq!(args.warning_days, 30);
    assert_eq!(args.format, "text");
    assert!(args.ca_file.is_none());
    assert_eq!(args.timeout, 10);
    assert_eq!(args.concurrent, 1);
}

#[test]
fn test_parse_args_with_options() {
    let args = Args::try_parse_from([
        "cert-checker",
        "example.com",
        "--warning-days", "15",
        "--format", "json",
        "--ca-file", "/path/to/certs",
        "--timeout", "60",
        "-j", "5"
    ]).unwrap();
    assert_eq!(args.urls, vec!["example.com"]);
    assert_eq!(args.warning_days, 15);
    assert_eq!(args.format, "json");
    assert_eq!(args.ca_file.unwrap().to_string_lossy(), "/path/to/certs");
    assert_eq!(args.timeout, 60);
    assert_eq!(args.concurrent, 5);
}

#[test]
fn test_parse_args_multiple_urls() {
    let args = Args::try_parse_from([
        "cert-checker",
        "example.com",
        "github.com",
        "google.com",
        "-j", "3"
    ]).unwrap();
    assert_eq!(args.urls, vec!["example.com", "github.com", "google.com"]);
    assert_eq!(args.concurrent, 3);
}

#[test]
fn test_parse_args_with_invalid_options() {
    let result = Args::try_parse_from(["cert-checker"]);
    assert!(result.is_err());
} 