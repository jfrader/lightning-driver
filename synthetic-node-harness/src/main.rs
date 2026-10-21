use chrono::Utc;
use clap::Parser;
use lightning_client::{model::Backend, settings::Settings};
use serde_json::json;
use std::{io::Write, os::unix::fs::OpenOptionsExt};
use synthetic_node_harness::Harness;

const DEVELOPMENT_API_PORT: u16 = 8080;

#[derive(Parser)]
struct Arguments {
    #[arg(long, required = true)]
    acknowledge_synthetic_dev: bool,
    /// Browser-facing loopback port; the API listener stays on 127.0.0.1:8080.
    #[arg(long, default_value_t = DEVELOPMENT_API_PORT, value_parser = clap::value_parser!(u16).range(1..))]
    public_port: u16,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments = Arguments::parse();
    let public_origin = format!("http://localhost:{}", arguments.public_port);
    let mut harnesses = Vec::new();
    let mut nodes = Vec::new();
    for (backend, id) in [
        (Backend::ClnRest, "cln"),
        (Backend::LndRest, "lnd-rest"),
        (Backend::LndGrpc, "lnd-grpc"),
    ] {
        let harness = Harness::start(backend, "127.0.0.1:0".parse()?, 77, Utc::now()).await?;
        nodes.push(harness.node_configuration(id));
        harnesses.push(harness);
    }
    let directory = harnesses[0].directory();
    let path = directory.join("config.json");
    let config = json!({"nodes":nodes,"api":{"bind":format!("127.0.0.1:{DEVELOPMENT_API_PORT}"),"public_origin":public_origin,"rp_id":"localhost","database":"manager.sqlite","invoice_key_file":"invoice.key","allow_insecure_loopback":true,"limits":{"rpc_seconds":1}}});
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?
        .write_all(&serde_json::to_vec_pretty(&config)?)?;
    Settings::load(&path)?;
    println!("Synthetic nodes only. In separate terminals, from the workspace root:\n\ncargo run -p api-server -- serve --config {}\ncargo run -p api-server -- auth enrollment --config {}\n\nBrowser origin: {public_origin}\nAPI listener: http://127.0.0.1:{DEVELOPMENT_API_PORT}\nStop the API before stopping this harness (Ctrl-C removes the disposable state).",path.display(),path.display());
    tokio::signal::ctrl_c().await?;
    for harness in harnesses {
        harness.stop().await;
    }
    Ok(())
}
