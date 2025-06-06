# Cert-Checker

A command-line tool to check SSL/TLS certificates for secure websites. This tool helps you verify the validity, expiration dates, and other important information about SSL/TLS certificates and their certificate chains.

## Features

- Check complete certificate chain (server, intermediate, and root certificates)
- Display detailed certificate information for each certificate in the chain
- Verify chain validity and individual certificate status
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
# Check HTTPS certificate chain
cert-checker https://example.com

# Check with just domain (defaults to HTTPS)
cert-checker example.com
```

With options:
```bash
# Output in JSON format
cert-checker -f json https://example.com

# Enable verbose output
cert-checker -v https://example.com

# Set custom warning threshold (in days)
cert-checker -w 60 https://example.com

# Use custom certificate store (directory containing .pem or .crt files)
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
================================================================================
Certificate Chain Status: ✓ Valid
================================================================================

--------------------------------------------------------------------------------
Certificate #1 (SERVER)
--------------------------------------------------------------------------------

Basic Information:
  Subject: CN=example.com
  Issuer:  CN=Intermediate CA

Validity Period:
  Valid From:  2024-01-01 00:00:00 UTC
  Valid Until: 2024-12-31 23:59:59 UTC

Technical Details:
  Serial Number:        1234567890
  Signature Algorithm:  SHA256withRSA

Status Information:
  ✓ Certificate is VALID
  ✓ Days until expiry: 365

--------------------------------------------------------------------------------
Certificate #2 (INTERMEDIATE)
--------------------------------------------------------------------------------
...

================================================================================
```

### JSON Output
```json
{
  "is_chain_valid": true,
  "certificates": [
    {
      "type": "server",
      "valid_from": "2024-01-01T00:00:00Z",
      "valid_until": "2024-12-31T23:59:59Z",
      "issuer": "CN=Intermediate CA",
      "subject": "CN=example.com",
      "serial_number": "1234567890",
      "signature_algorithm": "SHA256withRSA",
      "is_valid": true,
      "is_expired": false,
      "is_not_yet_valid": false,
      "days_until_expiry": 365,
      "warning": ""
    },
    {
      "type": "intermediate",
      "valid_from": "2023-01-01T00:00:00Z",
      "valid_until": "2025-12-31T23:59:59Z",
      "issuer": "CN=Root CA",
      "subject": "CN=Intermediate CA",
      "serial_number": "0987654321",
      "signature_algorithm": "SHA256withRSA",
      "is_valid": true,
      "is_expired": false,
      "is_not_yet_valid": false,
      "days_until_expiry": 730,
      "warning": ""
    }
  ]
}
```

## Certificate Chain Information

The tool checks and displays information for the complete certificate chain, which typically includes:

1. **Server Certificate**
   - The website's own certificate
   - Contains the domain name and public key
   - Signed by an intermediate certificate

2. **Intermediate Certificate**
   - Issued by a trusted Certificate Authority
   - Links the server certificate to the root certificate
   - May be part of a chain of intermediate certificates

3. **Root Certificate**
   - The top-level certificate in the chain
   - Self-signed by a trusted Certificate Authority
   - Used to verify the entire chain

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

# Format and lint (required by CI)
cargo fmt -- --check
cargo clippy -- -D warnings
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
6. Ensure `cargo fmt -- --check`, `cargo clippy -- -D warnings` and `cargo test` all pass

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [rustls](https://github.com/rustls/rustls) - Modern TLS library in Rust
- [tokio](https://tokio.rs/) - Async runtime for Rust
- [clap](https://clap.rs/) - Command line argument parser 