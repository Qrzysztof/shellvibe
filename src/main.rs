mod config;
mod model;
mod policy;
mod process;
mod schema;
mod server;

use anyhow::Context;
use clap::Parser;
use config::{Cli, Config};
use rmcp::{ServiceExt, transport::io::stdio};
use server::ShellVibe;
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("shellvibe=info")),
        )
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let cli = Cli::parse();
    let config = Config::try_from(cli).context("invalid shellvibe configuration")?;
    let server = ShellVibe::new(config);
    let shutdown = server.clone();

    info!(policy = %server.policy_name(), "starting shellvibe MCP server on stdio");

    let service = server
        .serve(stdio())
        .await
        .context("failed to start MCP stdio service")?;
    let cancellation = service.cancellation_token();
    let mut service_task = tokio::spawn(service.waiting());

    let service_join = tokio::select! {
        result = &mut service_task => result,
        signal = shutdown_signal() => {
            if let Err(error) = signal {
                tracing::error!(%error, "failed to listen for shutdown signal");
            } else {
                info!("shutdown signal received");
            }
            cancellation.cancel();
            service_task.await
        }
    };

    // The stdio connection and OS shutdown signals define this local server's
    // lifetime. Stop process trees before clearing protocol Task state.
    shutdown.shutdown().await;

    let service_result = service_join.context("MCP service waiter task panicked")?;
    service_result.context("MCP service stopped with an error")?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> std::io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> std::io::Result<()> {
    tokio::signal::ctrl_c().await
}
