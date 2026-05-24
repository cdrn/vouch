// vouch-signer: a ceremony participant exposed as a service.
//
// v0 ships a single instance; the protocol surface is N-party so a
// future deployment can run as one of many federated signers without
// breaking clients.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!("vouch-signer starting");
    Ok(())
}
