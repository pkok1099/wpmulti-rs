//! Binary entry point for `wpmulti`.

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    wpmulti::cli::run_cli().await
}
