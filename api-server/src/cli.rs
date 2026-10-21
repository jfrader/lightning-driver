use crate::{
    app::application,
    runtime::{open_auth_store, Runtime, StartupError},
};
use actix_web::HttpServer;
use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use lightning_client::settings::Settings;
use std::{
    io::{self, Write},
    path::PathBuf,
    time::Duration,
};

const HTTP_WORKERS: usize = 2;

#[derive(Parser)]
#[command(
    name = "api-server",
    version,
    about = "Single-operator passkey API (auth/config checkpoint)"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve the /api/v1 passkey, session and safe configuration API.
    Serve(Config),
    /// Host-authorized authenticator enrollment and recovery.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
}

#[derive(Args)]
struct Config {
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum AuthCommand {
    /// Print one expiring enrollment token. Existing authenticators are preserved.
    Enrollment(Config),
    /// Revoke all passkeys/sessions and print a new enrollment token. Operations are preserved.
    Recovery {
        #[command(flatten)]
        config: Config,
        #[arg(long)]
        confirm_reset_authentication: bool,
    },
}

pub async fn execute(cli: Cli) -> Result<(), StartupError> {
    match cli.command {
        Command::Serve(config) => serve(load(config)?).await,
        Command::Auth { command } => {
            let (config, recover) = match command {
                AuthCommand::Enrollment(config) => (config, false),
                AuthCommand::Recovery {
                    config,
                    confirm_reset_authentication,
                } => {
                    if !confirm_reset_authentication {
                        return Err(StartupError::Confirmation);
                    }
                    (config, true)
                }
            };
            let settings = load(config)?;
            let journal = open_auth_store(&settings).await?;
            let token = journal
                .issue_enrollment(
                    Utc::now(),
                    Duration::from_secs(u64::from(settings.api.limits.preauth_seconds)),
                    recover,
                )
                .await
                .map_err(|_| StartupError::Storage)?;
            let mut stdout = io::stdout().lock();
            writeln!(stdout, "{}", token.as_str()).map_err(|_| StartupError::Output)?;
            stdout.flush().map_err(|_| StartupError::Output)
        }
    }
}

fn load(config: Config) -> Result<Settings, StartupError> {
    Settings::load(&config.config).map_err(|_| StartupError::Configuration)
}

async fn serve(settings: Settings) -> Result<(), StartupError> {
    let runtime = Runtime::prepare(&settings).await?;
    let state = runtime.state.clone();
    let server = HttpServer::new(move || application(state.clone()))
        .workers(HTTP_WORKERS)
        .bind(settings.api.bind)
        .map_err(|_| StartupError::Listener)?;
    for address in server.addrs() {
        eprintln!("API listening on {address}");
    }
    let server = server.run();
    let result = server.await.map_err(|_| StartupError::Listener);
    drop(runtime);
    result
}
