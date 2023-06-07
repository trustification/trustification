mod pods;

use std::{
    collections::{HashMap, HashSet},
    fmt::Debug,
    hash::Hash,
    sync::Arc,
};

pub use pods::image_store;
use tokio::sync::RwLock;

use crate::pubsub::{State, Subscription};

#[derive(Clone)]
pub struct Store<K, O, V>
where
    K: Clone + Debug + Eq + Hash,
    O: Clone + Debug + Eq + Hash,
    V: Clone + Debug + PartialEq,
{
    inner: Arc<RwLock<Inner<K, O, V>>>,
}

impl<K, O, V> Default for Store<K, O, V>
where
    K: Clone + Debug + Eq + Hash,
    O: Clone + Debug + Eq + Hash,
    V: Clone + Debug + PartialEq,
{
    fn default() -> Self {
        Self {
            inner: Default::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct Owned<O, V>
where
    O: Eq + Hash,
    V: PartialEq,
{
    pub owners: HashSet<O>,
    pub state: V,
}

impl<O, V> Default for Owned<O, V>
where
    O: Eq + Hash,
    V: PartialEq + Default,
{
    fn default() -> Self {
        Self {
            owners: Default::default(),
            state: Default::default(),
        }
    }
}

pub struct Inner<K, O, V>
where
    K: Clone + Debug + Eq + Hash,
    O: Clone + Debug + Eq + Hash,
    V: Clone + Debug + PartialEq,
{
    /// pods, with their images
    ///
    /// This is mainly needed to figure out how to clean up a pod which got removed.
    pods: HashMap<O, HashSet<K>>,

    /// listeners
    state: State<K, Owned<O, V>>,
}

impl<K, O, V> Default for Inner<K, O, V>
where
    K: Clone + Debug + Eq + Hash,
    O: Clone + Debug + Eq + Hash,
    V: Clone + Debug + PartialEq,
{
    fn default() -> Self {
        Self {
            pods: Default::default(),
            state: Default::default(),
        }
    }
}

impl<K, O, V> Inner<K, O, V>
where
    K: Clone + Debug + Eq + Hash + Send + Sync + 'static,
    O: Clone + Debug + Eq + Hash + Send + Sync + 'static,
    V: Clone + Debug + PartialEq + Send + Sync + 'static,
{
    /// add or modify an existing pod
    async fn apply<I, A>(&mut self, owner_ref: O, keys: HashSet<K>, initial: I, apply: A)
    where
        I: Fn(&K) -> V,
        A: Fn(&K, V) -> V,
    {
        if let Some(current) = self.pods.get(&owner_ref) {
            if current == &keys {
                // equal, nothing to do
                return;
            }

            // delete pod, and continue adding
            self.delete(&owner_ref, &apply).await;
        }

        // now we can be sure we need to add it

        // add images

        for image in &keys {
            self.state
                .mutate_state(image.clone(), |state| match state {
                    Some(mut state) => {
                        state.owners.insert(owner_ref.clone());
                        state.state = apply(image, state.state);
                        Some(state)
                    }
                    None => Some(Owned {
                        owners: HashSet::from_iter([owner_ref.clone()]),
                        state: initial(image),
                    }),
                })
                .await;
        }

        // add pod
        self.pods.insert(owner_ref, keys);
    }

    /// delete a pod
    async fn delete<A>(&mut self, pod_ref: &O, apply: A)
    where
        A: Fn(&K, V) -> V,
    {
        if let Some(images) = self.pods.remove(pod_ref) {
            // we removed a pod, so let's clean up its images

            for image in images {
                self.state
                    .mutate_state(image.clone(), |state| {
                        if let Some(mut state) = state {
                            state.owners.remove(pod_ref);
                            if state.owners.is_empty() {
                                None
                            } else {
                                state.state = apply(&image, state.state);
                                Some(state)
                            }
                        } else {
                            None
                        }
                    })
                    .await;
            }
        }
    }

    /// full reset of the state
    async fn reset(&mut self, images: HashMap<K, Owned<O, V>>, pods: HashMap<O, HashSet<K>>) {
        self.pods = pods;
        self.state.set_state(images).await;
    }
}

impl<K, O, V> Store<K, O, V>
where
    K: Clone + Debug + Eq + Hash + Send + Sync + 'static,
    O: Clone + Debug + Eq + Hash + Send + Sync + 'static,
    V: Clone + Debug + PartialEq + Send + Sync + 'static,
{
    #[allow(unused)]
    pub async fn get_state(&self) -> HashMap<K, Owned<O, V>> {
        self.inner.read().await.state.get_state().await
    }

    pub async fn subscribe(&self, buffer: impl Into<Option<usize>>) -> Subscription<K, Owned<O, V>> {
        self.inner.read().await.state.subscribe(buffer).await
    }
}
