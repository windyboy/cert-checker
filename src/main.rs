use anyhow::Result;
use cert_checker::cli::parse_args;
use cert_checker::core::check_certificate;
use cert_checker::utils::display_certificate_info;
use std::process;
use tracing::{info, error, Level};
use tracing_subscriber::FmtSubscriber;
use futures::stream::{self, StreamExt};
use std::collections::HashMap;
use colored::*;

/// Main entry point for the certificate checker
///
/// # Returns
///
/// A `Result` containing `()` if successful, or an error if something goes wrong
#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing with a more compact format
    FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .with_thread_names(false)
        .with_ansi(true)
        .with_level(true)
        .with_timer(tracing_subscriber::fmt::time::UtcTime::rfc_3339())
        .compact()
        .init();

    // Parse command-line arguments
    let args = match parse_args() {
        Ok(args) => {
            info!("{}", format!("Checking {} URLs...", args.urls.len()).cyan());
            args
        },
        Err(e) => {
            error!("{}", format!("Failed to parse arguments: {}", e).red());
            process::exit(1);
        }
    };

    // Process URLs in parallel with the specified concurrency limit
    let results: HashMap<String, _> = stream::iter(args.urls)
        .map(|url| async {
            let result = check_certificate(&url, args.warning_days, args.concurrent).await;
            (url, result)
        })
        .buffer_unordered(args.concurrent)
        .collect()
        .await;

    // Display results
    let mut has_errors = false;
    for (url, result) in results {
        match result {
            Ok(chain) => {
                info!("{}", format!("✓ {}", url).green());
                match display_certificate_info(&chain, &args.format, args.warning_days) {
                    Ok(output) => {
                        // Add a blank line before the results for better separation
                        println!("\n{}", format!("Results for {}:", url).bold());
                        println!("{}", output);
                    },
                    Err(e) => {
                        error!("{}", format!("Error displaying results for {}: {}", url, e).red());
                        has_errors = true;
                    }
                }
            }
            Err(e) => {
                error!("{}", format!("✗ {}: {}", url, e).red());
                has_errors = true;
            }
        }
    }

    if has_errors {
        process::exit(1);
    }

    info!("{}", "Certificate checks completed.".green());
    Ok(())
}
