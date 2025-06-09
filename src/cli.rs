use clap::Parser;
use std::path::PathBuf;

/// Command-line arguments for the certificate checker
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// The URL(s) to check (e.g., example.com or https://example.com)
    /// Can be specified multiple times for batch processing
    #[arg(required = true)]
    pub urls: Vec<String>,

    /// Number of days before expiry to show a warning
    #[arg(short, long, default_value = "30")]
    pub warning_days: u32,

    /// Output format (text, json)
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// Path to a custom CA certificate file
    #[arg(short, long)]
    pub ca_file: Option<PathBuf>,

    /// Timeout in seconds for the connection
    #[arg(short, long, default_value = "10")]
    pub timeout: u64,

    /// Number of concurrent checks (default: 1)
    #[arg(short = 'j', long, default_value = "1")]
    pub concurrent: usize,
}

/// Parse command-line arguments
///
/// # Returns
///
/// A `Result` containing the parsed arguments if successful, or a `clap::Error` if an error occurs
///
/// # Examples
///
/// ```
/// use cert_checker::cli::Args;
/// use clap::Parser;
/// let args = Args::try_parse_from(["cert-checker", "example.com"]);
/// assert!(args.is_ok());
/// ```
#[allow(dead_code)]
pub fn parse_args() -> Result<Args, clap::Error> {
    Args::try_parse()
} 