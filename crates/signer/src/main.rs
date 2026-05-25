use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vouch_signer=info".into()),
        )
        .init();

    let addr =
        std::env::var("VOUCH_SIGNER_ADDR").unwrap_or_else(|_| "127.0.0.1:8089".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(%addr, "vouch-signer listening");

    axum::serve(listener, vouch_signer::router()).await?;
    Ok(())
}
