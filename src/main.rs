mod cli;
mod core;
mod utils;

use anyhow::Result;
use tracing::info;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    // Parse command line arguments
    let args = cli::parse_args()?;
    
    info!("Starting certificate check");
    
    // Check certificate
    let cert_info = core::check_certificate(&args.url).await?;
    
    // Display results
    utils::display_certificate_info(&cert_info, args.warning_days, &args.format)?;
    
    info!("Certificate check completed");
    Ok(())
}
