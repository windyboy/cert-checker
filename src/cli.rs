use clap::Parser;
use anyhow::Result;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// URL to check (e.g., https://example.com)
    #[arg(required = true)]
    pub url: String,

    /// Output format (text/json)
    #[arg(short, long, default_value = "text")]
    pub format: String,

    /// Enable verbose output
    #[arg(short, long)]
    pub verbose: bool,

    /// Custom certificate store path
    #[arg(short, long)]
    pub cert_store: Option<String>,

    /// Warning threshold in days for certificate expiration
    #[arg(short, long, default_value = "30")]
    pub warning_days: u32,
}

pub fn parse_args() -> Result<Args> {
    Ok(Args::parse())
} 