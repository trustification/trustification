use crate::pubsub::State;
use bommer_api::data::{Event, Image, ImageRef};
use std::future::Future;
use std::ops::Deref;
use tracing::log;

#[derive(Clone, Debug, Default)]
pub struct WorkloadState {
    state: State<ImageRef, Image>,
}

impl Deref for WorkloadState {
    type Target = State<ImageRef, Image>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

pub async fn by_ns(
    source: &WorkloadState,
    namespace: impl Into<String>,
) -> (WorkloadState, impl Future<Output = anyhow::Result<()>>) {
    let workload = WorkloadState::default();
    let mut sub = source.subscribe(None).await;

    let runner = {
        let workload = workload.clone();
        let namespace = namespace.into();
        async move {
            while let Some(evt) = sub.recv().await {
                match evt {
                    Event::Added(image_ref, image) => {
                        workload
                            .mutate_state(image_ref, |_current| {
                                Some(Image {
                                    sbom: image.sbom,
                                    pods: image
                                        .pods
                                        .into_iter()
                                        .filter(|pod| pod.namespace == namespace)
                                        .collect(),
                                })
                            })
                            .await;
                    }
                    Event::Removed(image_ref) => {
                        workload.remove_state(image_ref).await;
                    }
                    Event::Modified(image_ref, image) => {
                        workload
                            .mutate_state(image_ref, |mut current| {
                                if let Some(state) = &mut current {
                                    state.pods = image
                                        .pods
                                        .into_iter()
                                        .filter(|pod| pod.namespace == namespace)
                                        .collect();
                                    state.sbom = image.sbom;
                                }

                                current
                            })
                            .await;
                    }
                    Event::Restart(mut state) => {
                        for s in state.values_mut() {
                            s.pods.retain(|pod| pod.namespace == namespace);
                        }
                        state.retain(|_, v| !v.pods.is_empty());
                        workload.set_state(state).await;
                    }
                }
            }
            log::info!("Lost subscription, re-trying...");

            Ok(())
        }
    };

    (workload, runner)
}
