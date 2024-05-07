use std::process::ExitCode;

mod delete;
mod reindex;
mod upload;

#[derive(clap::Subcommand, Debug)]
pub enum Command {
    #[command(subcommand)]
    Reindex(reindex::Reindex),
    #[command(subcommand)]
    Delete(delete::Delete),
    #[command(subcommand)]
    Upload(upload::Upload),
}

impl Command {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        if let Err(e) = env_logger::builder().format_timestamp_millis().try_init() {
            eprintln!("Error initializing logging: {:?}", e);
        }
        match self {
            Self::Reindex(reindex) => reindex.run().await,
            Self::Delete(delete) => delete.run().await,
            Self::Upload(upload) => upload.run().await,
        }
    }
}
