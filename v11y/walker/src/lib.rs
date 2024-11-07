use anyhow::Context;
use collector_osv::client::schema::SeverityType;
use collector_osv::client::OsvClient;
use cve::published::Metric;
use cve::Published;
use prometheus::Registry;
use serde_json::json;
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

                    log::info!("Filters: {}", filter.len());
                    log::info!("Prefixes: {:?}", self.require_prefix);

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

                        let mut name_matches_prefix = false;
                        for prefix in &self.require_prefix {
                            if name.starts_with(prefix) {
                                name_matches_prefix = true;
                                continue;
                            }
                        }
                        match name_matches_prefix {
                            true => (),
                            false => continue 'entry,
                        }

                        if let Some(key) = name.strip_suffix(".json") {
                            if last_delta.is_none() || filter.contains(&key.to_string()) {
                                files.push((key.to_string(), entry.path().to_path_buf()));
                            }
                        }
                    }

                    files.sort_unstable();

                    log::info!("Processing {} files", files.len());

                    let osv_client = OsvClient::default();
                    for (key, path) in files.iter().rev() {
                        log::info!("Processing: {key}");
                        let data = Self::get_cve_data(&osv_client, path).await?;

                        const MAX_RETRIES: usize = 10;
                        for retry in 0..MAX_RETRIES {
                            match storage.put_json_slice(key.into(), &data).await {
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

    async fn get_cve_data(osv_client: &OsvClient, path_buf: &PathBuf) -> anyhow::Result<Vec<u8>> {
        let data = tokio::fs::read(path_buf).await?;

        // Just interested in Published CVE because for Rejected CVE the 'cna' field has no 'metrics' field
        if let Ok(mut cve) = serde_json::from_slice::<Published>(&data) {
            let cvss_metric_not_provided = cve
                .containers
                .cna
                .metrics
                .iter()
                .filter(|metric| metric.cvss_v2_0.is_some() || metric.cvss_v3_0.is_some() || metric.cvss_v3_1.is_some())
                .collect::<Vec<&Metric>>()
                .is_empty();
            if cvss_metric_not_provided {
                let result = osv_client.vulns(&cve.metadata.id).await;
                match result {
                    Ok(option) => {
                        if let Some(vulnerability) = option {
                            if let Some(severities) = &vulnerability.severity {
                                for severity in severities {
                                    let mut metric = Metric {
                                        format: None,
                                        scenarios: vec![],
                                        cvss_v3_1: None,
                                        cvss_v3_0: None,
                                        cvss_v2_0: None,
                                        other: None,
                                    };
                                    if matches!(severity.severity_type, SeverityType::CVSSv3) {
                                        let vector_string = json!({ "vectorString": &severity.score });
                                        match &severity.score.get(..8) {
                                            Some("CVSS:3.1") => metric.cvss_v3_1 = Some(vector_string),
                                            Some("CVSS:3.0") => metric.cvss_v3_0 = Some(vector_string),
                                            _ => {}
                                        }
                                        cve.containers.cna.metrics.push(metric);
                                        log::info!(
                                            "Enhanced CVE {} with vectorString {}",
                                            &cve.metadata.id,
                                            &severity.score
                                        );
                                    } else if matches!(severity.severity_type, SeverityType::CVSSv2) {
                                        let vector_string = json!({ "vectorString": &severity.score });
                                        metric.cvss_v2_0 = Some(vector_string);
                                        cve.containers.cna.metrics.push(metric);
                                        log::info!(
                                            "Enhanced CVE {} with vectorString {}",
                                            &cve.metadata.id,
                                            &severity.score
                                        );
                                    }
                                }
                                return serde_json::to_vec::<Published>(&cve)
                                    .context("CVE should have been serialized into Vec<u8>");
                            }
                        }
                    }
                    Err(err) => log::warn!(
                        "Failed to get vulnerability from OSV for CVE {} ({})",
                        &cve.metadata.id,
                        err
                    ),
                }
            }
        }
        Ok(data)
    }
}

#[cfg(test)]
mod test {
    use crate::Run;
    use collector_osv::client::OsvClient;
    use cve::Published;
    use std::path::PathBuf;

    #[tokio::test]
    async fn test_get_cve_data_cvss31() {
        let vec = Run::get_cve_data(&OsvClient::new(), &PathBuf::from(r"../testdata/CVE-2023-33201.json"))
            .await
            .unwrap();
        assert_eq!(vec.len(), 1637);
        if let Ok(cve) = serde_json::from_slice::<Published>(&vec) {
            assert_eq!(cve.containers.cna.metrics.len(), 1);
            assert!(
                cve.containers.cna.metrics[0].cvss_v3_1.as_ref().unwrap()["vectorString"]
                    .as_str()
                    .unwrap()
                    .starts_with("CVSS:3.1")
            );
        }
    }

    #[tokio::test]
    async fn test_get_cve_data_cvss30() {
        let vec = Run::get_cve_data(&OsvClient::new(), &PathBuf::from(r"../testdata/CVE-2017-13052.json"))
            .await
            .unwrap();
        assert_eq!(vec.len(), 1701);
        if let Ok(cve) = serde_json::from_slice::<Published>(&vec) {
            assert_eq!(cve.containers.cna.metrics.len(), 1);
            assert!(
                cve.containers.cna.metrics[0].cvss_v3_0.as_ref().unwrap()["vectorString"]
                    .as_str()
                    .unwrap()
                    .starts_with("CVSS:3.0")
            );
        }
    }

    #[tokio::test]
    async fn test_get_cve_data_rejected() {
        let vec = Run::get_cve_data(&OsvClient::new(), &PathBuf::from(r"../testdata/CVE-2021-3601.json"))
            .await
            .unwrap();
        // original size is 1062 so the test ensures no changes are applied in case of a Rejected CVE
        assert_eq!(vec.len(), 1062);
    }

    #[tokio::test]
    async fn test_get_cve_data_metrics_not_empty_without_cvss() {
        let vec = Run::get_cve_data(&OsvClient::new(), &PathBuf::from(r"../testdata/CVE-2023-50164.json"))
            .await
            .unwrap();
        // assert_eq!(vec.len(), 1701);
        if let Ok(cve) = serde_json::from_slice::<Published>(&vec) {
            assert_eq!(cve.containers.cna.metrics.len(), 2);
            assert!(
                // the CVSS score is the 2nd element because metrics array wasn't empty
                cve.containers.cna.metrics[1].cvss_v3_1.as_ref().unwrap()["vectorString"]
                    .as_str()
                    .unwrap()
                    .eq("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
            );
        }
    }
}
