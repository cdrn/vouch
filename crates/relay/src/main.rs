// vouch-relay: dumb websocket message bus for FROST ceremonies.
//
// Sees session ids, ciphertexts, and timing; cannot decrypt, forge
// participation, or hold shares.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    tracing::info!("vouch-relay starting");
    Ok(())
}
