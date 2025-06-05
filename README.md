# Cert-Checker

A command-line tool to check SSL/TLS certificates for secure websites. This tool helps you verify the validity, expiration dates, and other important information about SSL/TLS certificates.

## Features

- Check certificate validity and expiration dates
- Display detailed certificate information
- Support for both text and JSON output formats
- Configurable warning threshold for certificate expiration
- Verbose logging for debugging
- Support for custom certificate stores

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cert-checker.git
cd cert-checker

# Build the project
cargo build --release

# The binary will be available at target/release/cert-checker
```

## Usage

Basic usage:
```bash
cert-checker https://example.com
```

With options:
```bash
# Output in JSON format
cert-checker -f json https://example.com

# Enable verbose output
cert-checker -v https://example.com

# Set custom warning threshold (in days)
cert-checker -w 60 https://example.com

# Use custom certificate store
cert-checker -c /path/to/certificates https://example.com
```

### Command Line Options

- `-f, --format <FORMAT>`: Output format (text/json) [default: text]
- `-v, --verbose`: Enable verbose output
- `-c, --cert-store <PATH>`: Custom certificate store path
- `-w, --warning-days <DAYS>`: Warning threshold in days for certificate expiration [default: 30]

## Output Examples

### Text Output
```
Certificate Information:
Valid from: 2024-01-01 00:00:00 UTC
Valid until: 2024-12-31 23:59:59 UTC
Issuer: CN=Example CA
Subject: CN=example.com
Serial Number: 1234567890
Signature Algorithm: SHA256withRSA
✓ Certificate is valid
```

### JSON Output
```json
{
  "valid_from": "2024-01-01T00:00:00Z",
  "valid_until": "2024-12-31T23:59:59Z",
  "issuer": "CN=Example CA",
  "subject": "CN=example.com",
  "serial_number": "1234567890",
  "signature_algorithm": "SHA256withRSA",
  "is_valid": true,
  "is_expired": false,
  "is_not_yet_valid": false,
  "days_until_expiry": 365,
  "warning": ""
}
```

## Development

### Prerequisites

- Rust 1.70 or later
- Cargo

### Building

```bash
# Debug build
cargo build

# Release build
cargo build --release

# Run tests
cargo test
```

### Running Tests

```bash
cargo test
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [rustls](https://github.com/rustls/rustls) - Modern TLS library in Rust
- [tokio](https://tokio.rs/) - Async runtime for Rust
- [clap](https://clap.rs/) - Command line argument parser 