use anyhow::Result;
use keymeld_enclave::run_vsock_server;

#[tokio::main]
async fn main() -> Result<()> {
    let vsock_port = std::env::var("VSOCK_PORT")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(5000);

    let enclave_id = std::env::var("ENCLAVE_ID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(0);

    run_vsock_server(vsock_port, enclave_id).await?;

    Ok(())
}
