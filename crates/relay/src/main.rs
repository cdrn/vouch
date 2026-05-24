use anyhow::Context;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vouch_relay=info,tower_http=info".into()),
        )
        .init();

    let addr =
        std::env::var("VOUCH_RELAY_ADDR").unwrap_or_else(|_| "127.0.0.1:8088".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .with_context(|| format!("binding {addr}"))?;
    tracing::info!(%addr, "vouch-relay listening");

    axum::serve(listener, vouch_relay::router()).await?;
    Ok(())
}
