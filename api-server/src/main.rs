use api_server::cli::{execute, Cli};
use clap::Parser;
use std::process::ExitCode;

#[actix_web::main]
async fn main() -> ExitCode {
    match execute(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
