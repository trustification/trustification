use std::{
    collections::{HashMap, HashSet},
    future::Future,
    pin::pin,
};

use bommer_api::data::{ImageRef, PodRef};
use futures::{Stream, TryStreamExt};
use k8s_openapi::api::core::v1::{ContainerStatus, Pod};
use kube::{runtime::watcher, Resource, ResourceExt};

use crate::store::{Owned, Store};

type Images = HashMap<ImageRef, Owned<PodRef, ()>>;
type Pods = HashMap<PodRef, HashSet<ImageRef>>;

pub fn image_store<S>(stream: S) -> (Store<ImageRef, PodRef, ()>, impl Future<Output = anyhow::Result<()>>)
where
    S: Stream<Item = Result<watcher::Event<Pod>, watcher::Error>>,
{
    let store = Store::<ImageRef, PodRef, ()>::default();
    let runner = {
        let store = store.clone();
        async move { run(store, stream).await }
    };

    (store, runner)
}

async fn run<S>(store: Store<ImageRef, PodRef, ()>, stream: S) -> anyhow::Result<()>
where
    S: Stream<Item = Result<watcher::Event<Pod>, watcher::Error>>,
{
    let mut stream = pin!(stream);

    while let Some(evt) = stream.try_next().await? {
        match evt {
            watcher::Event::Applied(pod) => {
                let pod_ref = match to_key(&pod) {
                    Some(pod_ref) => pod_ref,
                    None => continue,
                };

                let images = images_from_pod(pod);

                store.inner.write().await.apply(pod_ref, images, |_| (), |_, v| v).await;
            }
            watcher::Event::Deleted(pod) => {
                if let Some(pod_ref) = to_key(&pod) {
                    store.inner.write().await.delete(&pod_ref, |_, v| v).await;
                }
            }
            watcher::Event::Restarted(pods) => {
                let (images, pods) = to_state(pods);
                store.inner.write().await.reset(images, pods).await;
            }
        }
    }

    Ok(())
}

fn to_state(pods: Vec<Pod>) -> (Images, Pods) {
    let mut by_images: Images = Default::default();
    let mut by_pods = HashMap::new();

    for pod in pods {
        let pod_ref = match to_key(&pod) {
            Some(pod_ref) => pod_ref,
            None => continue,
        };

        let images = images_from_pod(pod);
        for image in &images {
            by_images
                .entry(image.clone())
                .or_default()
                .owners
                .insert(pod_ref.clone());
        }

        by_pods.insert(pod_ref, images);
    }

    (by_images, by_pods)
}

/// create a key for a pod
fn to_key(pod: &Pod) -> Option<PodRef> {
    match (pod.namespace(), pod.meta().name.clone()) {
        (Some(namespace), Some(name)) => Some(PodRef { namespace, name }),
        _ => None,
    }
}

/// collect all container images from a pod
fn images_from_pod(pod: Pod) -> HashSet<ImageRef> {
    pod.status
        .into_iter()
        .flat_map(|s| {
            s.container_statuses
                .into_iter()
                .flat_map(|c| c.into_iter().flat_map(to_container_id))
                .chain(
                    s.init_container_statuses
                        .into_iter()
                        .flat_map(|ic| ic.into_iter().flat_map(to_container_id)),
                )
                .chain(
                    s.ephemeral_container_statuses
                        .into_iter()
                        .flat_map(|ic| ic.into_iter().flat_map(to_container_id)),
                )
        })
        .collect()
}

pub fn to_container_id(container: ContainerStatus) -> Option<ImageRef> {
    if container.image_id.is_empty() {
        return None;
    }

    // FIXME: we need some more magic here, as kubernetes has weird ideas on filling the fields image and imageId.
    // see: docs/image_id.md

    // FIXME: this won't work on kind, and maybe others, as they generate broken image ID values
    Some(ImageRef(container.image_id))

    // ImageRef(format!("{} / {}", container.image, container.image_id))
}
