use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::SystemTime;
use std::{net::SocketAddr, sync::Arc, time::Duration};

use csaf_walker::discover::AsDiscovered;
use csaf_walker::report::{render, DocumentKey, Duplicates, RenderOptions, ReportResult};
use csaf_walker::{
    discover::DiscoveredAdvisory,
    retrieve::{RetrievedAdvisory, RetrievingVisitor},
    source::{FileSource, HttpSource},
    validation::{ValidatedAdvisory, ValidationError, ValidationVisitor},
    verification::{
        check::{init_verifying_visitor, CheckError},
        VerificationError, VerifiedAdvisory, VerifyingVisitor,
    },
    walker::Walker,
};
use reqwest::{header, StatusCode};
use serde::Deserialize;
use tokio::sync::{Mutex, RwLock};
use trustification_auth::client::{TokenInjector, TokenProvider};
use url::Url;
use walker_common::{
    fetcher::{Fetcher, FetcherOptions},
    since::Since,
    utils::url::Urlify,
    validate::ValidationOptions,
};

#[allow(clippy::too_many_arguments)]
pub async fn run(
    workers: usize,
    source: String,
    sink: Url,
    provider: Arc<dyn TokenProvider>,
    options: ValidationOptions,
    render_options: RenderOptions,
    ignore_distributions: Vec<Url>,
    since_file: Option<PathBuf>,
    additional_root_certificates: Vec<PathBuf>,
) -> Result<(), anyhow::Error> {
    let fetcher = Fetcher::new(Default::default()).await?;

    let mut client = reqwest::ClientBuilder::new();
    for cert in additional_root_certificates {
        let pem = std::fs::read(&cert)?;
        client = client.add_root_certificate(reqwest::tls::Certificate::from_pem(&pem)?);
    }

    let total = Arc::new(AtomicUsize::default());
    let duplicates: Arc<std::sync::Mutex<Duplicates>> = Default::default();
    let errors: Arc<std::sync::Mutex<BTreeMap<DocumentKey, String>>> = Default::default();
    let warnings: Arc<std::sync::Mutex<BTreeMap<DocumentKey, Vec<CheckError>>>> = Default::default();

    {
        let client = Arc::new(client.build()?);
        let total = total.clone();
        let duplicates = duplicates.clone();
        let errors = errors.clone();
        let warnings = warnings.clone();

        let visitor = move |advisory: Result<
            VerifiedAdvisory<ValidatedAdvisory, &'static str>,
            VerificationError<ValidationError, ValidatedAdvisory>,
        >| {
            (*total).fetch_add(1, Ordering::Release);

            let errors = errors.clone();
            let warnings = warnings.clone();
            let client = client.clone();
            let sink = sink.clone();
            let provider = provider.clone();
            async move {
                let adv = match advisory {
                    Ok(adv) => {
                        let sink = sink.clone();
                        let name = adv
                            .url
                            .path_segments()
                            .and_then(|s| s.last())
                            .unwrap_or_else(|| adv.url.path());
                        match client
                            .post(sink)
                            .header(header::CONTENT_TYPE, "application/json")
                            .body(serde_json::to_string(&adv.csaf.clone()).unwrap())
                            .inject_token(&provider)
                            .await?
                            .send()
                            .await
                        {
                            Ok(r) if r.status() == StatusCode::CREATED => {
                                log::info!("VEX ({}) stored successfully", &adv.csaf.document.tracking.id);
                            }
                            Ok(r) => {
                                log::warn!("(Skipped) {name}: Error storing VEX: {}", r.status());
                            }
                            Err(e) => {
                                log::warn!("(Skipped) {name}: Error storing VEX: {e:?}");
                            }
                        };
                        adv
                    }
                    Err(err) => {
                        let name = match err.as_discovered().relative_base_and_url() {
                            Some((base, relative)) => DocumentKey {
                                distribution_url: base.clone(),
                                url: relative,
                            },
                            None => DocumentKey {
                                distribution_url: err.url().clone(),
                                url: Default::default(),
                            },
                        };

                        // let name = err.url().to_string();

                        errors.lock().unwrap().insert(name, err.to_string());
                        return Ok::<_, anyhow::Error>(());
                    }
                };

                if !adv.failures.is_empty() {
                    let name = DocumentKey::for_document(&adv);
                    warnings
                        .lock()
                        .unwrap()
                        .entry(name)
                        .or_default()
                        .extend(adv.failures.into_values().flatten());
                }

                Ok::<_, anyhow::Error>(())
            }
        };
        let visitor = VerifyingVisitor::with_checks(visitor, init_verifying_visitor());
        let visitor = ValidationVisitor::new(visitor).with_options(options);

        if let Ok(url) = Url::parse(&source) {
            let since = Since::new(None::<SystemTime>, since_file, Default::default())?;
            log::info!("Walking VEX docs: source='{source}' workers={workers}");
            let source = HttpSource {
                url,
                fetcher,
                options: csaf_walker::source::HttpOptions { since: *since },
            };
            Walker::new(source.clone())
                .with_distribution_filter(Box::new(move |distribution| {
                    !ignore_distributions.contains(&distribution.directory_url)
                }))
                .walk_parallel(workers, RetrievingVisitor::new(source.clone(), visitor))
                .await?;

            since.store()?;
        } else {
            log::info!("Walking VEX docs: path='{source}' workers={workers}");
            let source = FileSource::new(source, None)?;
            Walker::new(source.clone())
                .with_distribution_filter(Box::new(move |distribution| {
                    !ignore_distributions.contains(&distribution.directory_url)
                }))
                .walk(RetrievingVisitor::new(source.clone(), visitor))
                .await?;
        }
    }

    let total = (*total).load(Ordering::Acquire);
    render(
        render_options,
        ReportResult {
            total,
            duplicates: &duplicates.lock().unwrap(),
            errors: &errors.lock().unwrap(),
            warnings: &warnings.lock().unwrap(),
        },
    )?;
    Ok(())
}

fn render(render: RenderOptions, report: ReportResult) -> anyhow::Result<()> {
    let mut out = std::fs::File::create(&render.output)?;
    render::render_to_html(&mut out, &report, &render)?;

    Ok(())
}
