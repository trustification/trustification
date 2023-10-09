mod data;
mod indexer;

use crate::indexer::Indexer;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::ExitCode;
use walkdir::WalkDir;

#[derive(clap::Args, Debug)]
#[command(about = "Run the api server", args_conflicts_with_subcommands = true)]
pub struct Run {
    /// Path of the database file
    #[arg(env, long = "storage-base", default_value = "./cves.db")]
    storage: PathBuf,
    /// The source directory
    #[arg(env, long = "source")]
    source: PathBuf,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        env_logger::init();

        log::info!("Indexing {} -> {}", self.source.display(), self.storage.display());

        let walker = WalkDir::new(self.source).follow_links(true).contents_first(true);

        let mut indexer = Indexer::new();

        for entry in walker {
            let entry = entry?;

            if !entry.file_type().is_file() {
                continue;
            }

            if entry.path().extension().and_then(OsStr::to_str) != Some("json") {
                continue;
            }

            let name = match entry.file_name().to_str() {
                None => continue,
                Some(name) => name,
            };

            if !name.starts_with("CVE-") {
                continue;
            }

            indexer.add(entry.path())?;
        }

        Ok(ExitCode::SUCCESS)
    }
}
