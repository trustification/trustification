use crate::health::Check;
use std::marker::PhantomData;
use std::sync::atomic::{AtomicBool, Ordering};

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
