use std::process::ExitCode;

use reqwest::StatusCode;
use trustification_common::tls::ClientConfig;

/// Reindex
#[derive(clap::Subcommand, Debug)]
pub enum Reindex {
    Status(ReindexStatus),
    Start(ReindexStart),
}

impl Reindex {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        match self {
            Self::Start(run) => run.run().await,
            Self::Status(run) => run.run().await,
        }
    }
}

#[derive(clap::Args, Debug)]
#[command(about = "Trigger reindex", args_conflicts_with_subcommands = true)]
pub struct ReindexStart {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[arg(short = 'i', long = "indexer", default_value = "http://localhost:8080/")]
    pub indexer_url: String,

    #[command(flatten)]
    pub client: ClientConfig,
}

impl ReindexStart {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        let client = self.client.build_client()?;
        match client.post(self.indexer_url).send().await {
            Ok(response) => {
                if response.status() == StatusCode::OK {
                    println!("Reindexing started successfully");
                } else {
                    let body = response.text().await;
                    println!("Error starting reindexing: {:?}", body);
                }
            }
            Err(e) => {
                println!("Error starting reindexing: {:?}", e);
            }
        }

        Ok(ExitCode::SUCCESS)
    }
}

#[derive(clap::Args, Debug)]
#[command(about = "Check reindex status", args_conflicts_with_subcommands = true)]
pub struct ReindexStatus {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[arg(short = 'i', long = "indexer", default_value = "http://localhost:8080/")]
    pub indexer_url: String,
}

impl ReindexStatus {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Ok(ExitCode::SUCCESS)
    }
}
