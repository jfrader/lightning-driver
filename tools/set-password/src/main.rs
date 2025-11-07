// tools/set-password/src/main.rs
use anyhow::{anyhow, Result};
use argon2::{Argon2, PasswordHasher};
use dialoguer::{theme::ColorfulTheme, Password};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use toml_edit::{value, DocumentMut, Item, Table};

fn main() -> Result<()> {
    println!("Set API password for rust-lightning-driver");

    let config_path = find_config_toml()?;
    println!("Using config: {}", config_path.display());

    let password = Password::with_theme(&ColorfulTheme::default())
        .with_prompt("Enter new password")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;

    let salt = argon2::password_hash::SaltString::encode_b64(b"rustlightning123")
        .map_err(|e| anyhow!("Salt encoding failed: {}", e))?;
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow!("Hashing failed: {}", e))?
        .to_string();

    let content = fs::read_to_string(&config_path)?;
    let mut doc = content.parse::<DocumentMut>()?;
    let api_table = doc
        .entry("api")
        .or_insert_with(|| Item::Table(Table::new()));
    if let Item::Table(table) = api_table {
        table["password_hash"] = value(hash.clone());
        table.fmt();
    }
    fs::write(&config_path, doc.to_string())?;
    println!("Password hash updated in {}", config_path.display());
    println!("Hash: {hash}");

    let repo_root = config_path.parent().unwrap();
    let session_key_path = repo_root.join("session_key.bin");
    if session_key_path.exists() {
        fs::remove_file(&session_key_path)?;
        println!("Deleted old session key: {}", session_key_path.display());
    } else {
        println!("No existing session_key.bin to delete.");
    }

    Ok(())
}

// Find config.toml at workspace root (robust)
fn find_config_toml() -> Result<PathBuf> {
    // 1. Use CARGO_MANIFEST_DIR (set by `cargo run`) - go up 2 levels for tools/set-password
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let path = Path::new(&manifest_dir)
            .join("..")
            .join("..")
            .join("config.toml");
        if path.exists() {
            return Ok(path.canonicalize()?);
        }
    }

    // 2. Fallback: walk up from current exe
    let exe = env::current_exe()?;
    let mut dir = exe
        .parent()
        .ok_or_else(|| anyhow!("No parent dir"))?
        .to_path_buf();

    for _ in 0..20 {
        let candidate = dir.join("config.toml");
        if candidate.exists() {
            return Ok(candidate.canonicalize()?);
        }
        if !dir.pop() {
            break;
        }
    }

    Err(anyhow!(
        "config.toml not found. Place it in the project root and run via `cargo run -p set-password`"
    ))
}
