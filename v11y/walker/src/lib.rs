use prometheus::Registry;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::ExitCode;
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
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

    #[command(flatten)]
    pub infra: InfrastructureConfig,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run(
                "v11y-walker",
                |_context| async { Ok(()) },
                |_context| async move {
                    let storage = Storage::new(self.storage.process("v11y", self.devmode), &Registry::new())?;

                    let walker = WalkDir::new(&self.source).follow_links(true).contents_first(true);

                    let mut files = vec![];

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
                            files.push((key.to_string(), entry.path().to_path_buf()));
                        }
                    }

                    files.sort_unstable();

                    log::info!("Processing {} files", files.len());

                    for (key, path) in files.iter().rev() {
                        log::info!("Processing: {key}");
                        let data = tokio::fs::read(path).await?;

                        const MAX_RETRIES: usize = 10;
                        for retry in 0..MAX_RETRIES {
                            match storage.put_json_slice(key, &data).await {
                                Ok(_) => break,
                                Err(e) => {
                                    log::warn!("Failed to store {} (attempt {}/{}): {:?}", key, retry, MAX_RETRIES, e);
                                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                                    if retry == MAX_RETRIES - 1 {
                                        return Err(e)?;
                                    }
                                }
                            }
                        }
                    }

                    log::info!("Processed {} files", files.len());
                    Ok(())
                },
            )
            .await?;
        Ok(ExitCode::SUCCESS)
    }
}
