use crate::{
    journal::{validate_state_directory, Journal},
    state::ApplicationState,
};
use lightning_client::settings::Settings;
use std::{
    fs::{File, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::Path,
};

#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("Invalid configuration. Check the public origin, RP host and runtime limits.")]
    Configuration,
    #[error("Protected storage unavailable. Check the state directory and file permissions.")]
    Storage,
    #[error(
        "Another API instance owns this state directory, or its instance lock is unavailable."
    )]
    Instance,
    #[error("Recovery requires --confirm-reset-authentication; existing passkeys and sessions will be revoked.")]
    Confirmation,
    #[error("API listener unavailable or interrupted.")]
    Listener,
    #[error("Cannot write command output.")]
    Output,
}

pub struct Runtime {
    pub state: ApplicationState,
    _instance: File,
}

impl Runtime {
    pub async fn prepare(settings: &Settings) -> Result<Self, StartupError> {
        settings
            .validate()
            .map_err(|_| StartupError::Configuration)?;
        let instance = instance_lock(&settings.api.database)?;
        let state = open_application(settings).await?;
        state
            .engine
            .recover()
            .await
            .map_err(|_| StartupError::Storage)?;
        Ok(Self {
            state,
            _instance: instance,
        })
    }
}

pub async fn open_auth_store(settings: &Settings) -> Result<Journal, StartupError> {
    settings
        .validate()
        .map_err(|_| StartupError::Configuration)?;
    Journal::open(settings.api.database.clone())
        .await
        .map_err(|_| StartupError::Storage)
}

pub async fn open_application(settings: &Settings) -> Result<ApplicationState, StartupError> {
    settings
        .validate()
        .map_err(|_| StartupError::Configuration)?;
    let journal = Journal::open(settings.api.database.clone())
        .await
        .map_err(|_| StartupError::Storage)?;
    ApplicationState::new(settings, journal)
        .await
        .map_err(|_| StartupError::Storage)
}

fn instance_lock(database: &Path) -> Result<File, StartupError> {
    validate_state_directory(database).map_err(|_| StartupError::Storage)?;
    let mut name = database.as_os_str().to_os_string();
    name.push(".serve.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(Path::new(&name))
        .map_err(|_| StartupError::Instance)?;
    let metadata = file.metadata().map_err(|_| StartupError::Instance)?;
    if !metadata.is_file()
        || metadata.permissions().mode() & 0o077 != 0
        || metadata.uid() != rustix::process::geteuid().as_raw()
        || metadata.nlink() != 1
    {
        return Err(StartupError::Instance);
    }
    file.try_lock().map_err(|_| StartupError::Instance)?;
    Ok(file)
}
