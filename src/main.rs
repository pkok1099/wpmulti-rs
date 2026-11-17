//! Binary entry point for `wpmulti`.

use std::io::Write;

#[tokio::main]
async fn main() -> std::process::ExitCode {
    match wpmulti::cli::run_cli().await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(err) => {
            // Print the error via `Display`, not `Debug`: returning `Err`
            // from `main` would render `io::Error` as
            // `Custom { kind: Other, ... }`, hiding the actual message
            // behind Rust internals.
            let _ = writeln!(std::io::stderr().lock(), "Error: {err}");
            std::process::ExitCode::FAILURE
        }
    }
}
