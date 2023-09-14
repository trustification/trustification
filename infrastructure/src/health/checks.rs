use super::Check;
use async_trait::async_trait;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// A check which always fails.
///
/// This can be used as a placeholder, when a check cannot be registered during startup, but needs
/// to be added later. If the check would be initially missing, the health check run might report
/// a success (as no failed checks where present).
pub struct UninitializedCheck;

#[async_trait]
impl Check for UninitializedCheck {
    type Error = &'static str;

    async fn run(&self) -> Result<(), Self::Error> {
        Err("Check not yet initialized")
    }
}

pub struct SyncFnCheck<F, E>(pub F)
where
    F: Fn() -> Result<(), E> + Send + Sync,
    E: std::fmt::Display;

#[async_trait]
impl<F, E> Check for SyncFnCheck<F, E>
where
    F: Fn() -> Result<(), E> + Send + Sync,
    E: std::fmt::Display,
{
    type Error = E;

    async fn run(&self) -> Result<(), Self::Error> {
        (self.0)()
    }
}

pub fn sync<F, E>(f: F) -> SyncFnCheck<F, E>
where
    F: Fn() -> Result<(), E> + Send + Sync,
    E: std::fmt::Display,
{
    SyncFnCheck(f)
}

/// A check based on a state which has an [`AtomicBool`].
///
/// The state will be used to get the atomic boolean. If that is `true`, the check will be
/// [`State::Up`].
pub struct AtomicBoolStateCheck<'s, T, F>
where
    T: Send + Sync + 's,
    F: for<'f> Fn(&'f T) -> &'f AtomicBool + Send + Sync,
{
    state: T,
    extractor: F,
    error: String,
    _marker: PhantomData<&'s ()>,
}

impl<'s, T, F> AtomicBoolStateCheck<'s, T, F>
where
    T: Send + Sync + 's,
    F: for<'f> Fn(&'f T) -> &'f AtomicBool + Send + Sync,
{
    pub fn new(state: T, extractor: F, error: impl Into<String>) -> Self {
        Self {
            state,
            extractor,
            error: error.into(),
            _marker: Default::default(),
        }
    }
}

#[async_trait]
impl<'s, T, F> Check for AtomicBoolStateCheck<'s, T, F>
where
    T: Send + Sync + 's,
    F: for<'f> Fn(&'f T) -> &'f AtomicBool + Send + Sync,
{
    type Error = String;

    async fn run(&self) -> Result<(), Self::Error> {
        match (self.extractor)(&self.state).load(Ordering::Relaxed) {
            true => Ok(()),
            false => Err(self.error.clone()),
        }
    }
}

#[derive(Clone)]
pub struct Probe {
    state: Arc<AtomicBool>,
}

pub struct ProbeCheck {
    error: String,
    state: Arc<AtomicBool>,
}

impl Probe {
    /// Create a new probe, which initially is [`State::Down`].
    pub fn new(error: impl Into<String>) -> (Self, ProbeCheck) {
        let state = Arc::new(AtomicBool::default());
        (
            Self { state: state.clone() },
            ProbeCheck {
                error: error.into(),
                state,
            },
        )
    }

    /// Update the state of the probe
    pub fn set(&self, state: bool) {
        self.state.store(state, Ordering::Relaxed);
    }
}

#[async_trait]
impl Check for ProbeCheck {
    type Error = String;

    async fn run(&self) -> Result<(), Self::Error> {
        match self.state.as_ref().load(Ordering::Relaxed) {
            true => Ok(()),
            false => Err(self.error.clone()),
        }
    }
}
