use prometheus::Registry;
use std::collections::HashSet;
use std::ffi::OsStr;
use std::path::PathBuf;
use std::process::ExitCode;
use trustification_infrastructure::{Infrastructure, InfrastructureConfig};
use trustification_storage::{Storage, StorageConfig};
use walkdir::WalkDir;

mod delta;

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

    /// A file to read/store the last delta.
    #[arg(long = "delta-file")]
    pub delta_file: Option<PathBuf>,

    /// A list of required prefixed of the file name (e.g. CVE-2023-).
    // NOTE: we raise a conflict with delta_file to ensure that the delta processing works
    // consistently. Adding a prefix there might consider content as "processed" while it
    // indeed was not.
    #[arg(long = "prefix", conflicts_with = "delta_file")]
    pub require_prefix: Vec<String>,
}

impl Run {
    pub async fn run(self) -> anyhow::Result<ExitCode> {
        Infrastructure::from(self.infra)
            .run(
                "v11y-walker",
                |_context| async { Ok(()) },
                |_context| async move {
                    let storage = Storage::new(self.storage.process("v11y", self.devmode), &Registry::new())?;

                    let mut files = vec![];
                    let mut filter = HashSet::new();

                    let mut last_delta = None;
                    let delta_file = self.source.join("cves").join("delta.json");
                    if let Some(last_delta_file) = &self.delta_file {
                        if last_delta_file.exists() {
                            let delta: delta::Delta = serde_json::from_reader(std::fs::File::open(last_delta_file)?)?;
                            last_delta.replace(delta);
                        }
                        let log_file = self.source.join("cves").join("deltaLog.json");
                        if log_file.exists() && delta_file.exists() {
                            let delta_log: delta::DeltaLog = serde_json::from_reader(std::fs::File::open(&log_file)?)?;
                            let last_delta = last_delta
                                .as_ref()
                                .map(|d| d.fetch_time)
                                .unwrap_or(time::OffsetDateTime::UNIX_EPOCH);
                            log::info!("Last delta: {:?}", last_delta);
                            delta_log
                                .iter()
                                .filter(|delta| delta.number_of_changes > 0 && delta.fetch_time > last_delta)
                                .for_each(|delta| {
                                    log::trace!("Found newer delta: {:?}", delta);
                                    for new in delta.new.iter() {
                                        filter.insert(new.cve_id.clone());
                                    }
                                    for updated in delta.updated.iter() {
                                        filter.insert(updated.cve_id.clone());
                                    }
                                });
                        }
                    }

                    log::info!("Filters: {:?}", filter.len());

                    let walker = WalkDir::new(&self.source).follow_links(true).contents_first(true);
                    'entry: for entry in walker {
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

                        for prefix in &self.require_prefix {
                            if !name.starts_with(prefix) {
                                continue 'entry;
                            }
                        }

                        if let Some(key) = name.strip_suffix(".json") {
                            if last_delta.is_none() || filter.contains(&key.to_string()) {
                                files.push((key.to_string(), entry.path().to_path_buf()));
                            }
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
                    if let Some(last_delta_file) = &self.delta_file {
                        std::fs::copy(delta_file, last_delta_file)?;
                    }
                    Ok(())
                },
            )
            .await?;
        Ok(ExitCode::SUCCESS)
    }
}
