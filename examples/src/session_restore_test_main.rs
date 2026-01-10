//! Session Restoration Test Binary Entry Point

mod session_restore_test;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    session_restore_test::run().await
}
