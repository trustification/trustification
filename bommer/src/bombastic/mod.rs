mod client;

use std::{future::Future, time::Duration};

use anyhow::bail;
use bommer_api::data::{Event, Image, ImageRef, PodRef, SbomState, SBOM};
pub use client::BombasticSource;
use futures::FutureExt;
use log::{info, warn};
use packageurl::PackageUrl;

use crate::{pubsub::Output, store::Store, workload::WorkloadState};

pub fn store(
    store: Store<ImageRef, PodRef, ()>,
    source: BombasticSource,
) -> (WorkloadState, impl Future<Output = anyhow::Result<()>>) {
    let map = WorkloadState::default();

    (map.clone(), async move {
        let (result, _, _) = futures::future::select_all([
            runner(store, map.clone()).boxed_local(),
            scanner(map.clone(), source).boxed_local(),
            rescanner(map).boxed_local(),
        ])
        .await;

        result
    })
}

struct Scanner {
    map: WorkloadState,
    source: BombasticSource,
}

impl Scanner {
    async fn lookup(&self, image: &ImageRef) -> Result<Option<SBOM>, anyhow::Error> {
        if let Some((base, digest)) = image.0.rsplit_once('@') {
            if let Some(name) = base.split('/').last() {
                let mut purl = PackageUrl::new("oci", name)?;
                if digest.starts_with("sha256:") {
                    purl.with_version(digest);
                    return Ok::<_, anyhow::Error>(self.source.lookup_sbom(purl).await?);
                }
            }
        }
        bail!("Unable to create PURL for: {image}");
    }

    async fn scan(&self, image: &ImageRef) {
        let state = match self.lookup(image).await {
            Ok(Some(result)) => SbomState::Found(result),
            Ok(None) => SbomState::Missing,
            Err(err) => SbomState::Err(err.to_string()),
        };
        self.map
            .mutate_state(image.clone(), |current| {
                current.map(|mut current| {
                    current.sbom = state;
                    current
                })
            })
            .await;
    }
}

/// directly scan incoming changes
async fn scanner(map: WorkloadState, source: BombasticSource) -> anyhow::Result<()> {
    let scanner = Scanner {
        map: map.clone(),
        source,
    };

    loop {
        info!("Starting subscription ... ");
        let mut sub = map.subscribe(128).await;
        while let Some(evt) = sub.recv().await {
            // FIXME: need to parallelize processing
            match evt {
                Event::Added(image, state) | Event::Modified(image, state) => {
                    if let SbomState::Scheduled = state.sbom {
                        scanner.scan(&image).await;
                    }
                }
                Event::Restart(state) => {
                    for (image, state) in state {
                        if let SbomState::Scheduled = state.sbom {
                            scanner.scan(&image).await;
                        }
                    }
                }
                Event::Removed(_) => {}
            }
        }

        // lost subscription, delay and re-try
        warn!("Lost subscription");
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// periodically re-scan changes
async fn rescanner(map: WorkloadState) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(Duration::from_secs(15)).await;

        map.iter_mut(|_k, state| match &state.sbom {
            SbomState::Err(_) | SbomState::Missing => {
                let mut state = state.clone();
                state.sbom = SbomState::Scheduled;
                Output::Modify(state)
            }
            _ => Output::Keep,
        })
        .await;
    }
}

async fn runner(store: Store<ImageRef, PodRef, ()>, map: WorkloadState) -> anyhow::Result<()> {
    loop {
        let mut sub = store.subscribe(32).await;
        while let Some(evt) = sub.recv().await {
            match evt {
                Event::Added(image, state) | Event::Modified(image, state) => {
                    map.mutate_state(image, |current| match current {
                        Some(mut current) => {
                            current.pods = state.owners;
                            Some(current)
                        }
                        None => Some(Image {
                            pods: state.owners,
                            sbom: SbomState::Scheduled,
                        }),
                    })
                    .await;
                }
                Event::Removed(image) => {
                    map.mutate_state(image, |_| None).await;
                }
                Event::Restart(state) => {
                    map.set_state(
                        state
                            .into_iter()
                            .map(|(k, v)| {
                                (
                                    k,
                                    Image {
                                        pods: v.owners,
                                        sbom: SbomState::Scheduled,
                                    },
                                )
                            })
                            .collect(),
                    )
                    .await;
                }
            }
        }
    }
}
