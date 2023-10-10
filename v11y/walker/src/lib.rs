use prometheus::Registry;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::ExitCode;
use trustification_storage::{Storage, StorageConfig};
use walkdir::WalkDir;

#[derive(clap::Args, Debug)]
#[command(about = "Run the walker", args_conflicts_with_subcommands = true)]
pub struct Run {
    #[arg(long = "devmode", default_value_t = false)]
    pub devmode: bool,

    #[arg(long)]
    pub source: PathBuf,

    #[command(flatten)]
    pub storage: StorageConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        env_logger::init();

        let storage = Storage::new(self.storage.process("v11y", self.devmode), &Registry::new())?;

        let walker = WalkDir::new(&self.source).follow_links(true).contents_first(true);

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

            if let Some(key) = name.strip_suffix(".json") {
                log::info!("Processing: {key}");
                let data = tokio::fs::read(entry.path()).await?;
                storage.put_json_slice(key, &data).await?;
            }
        }

        Ok(ExitCode::SUCCESS)
    }
}
