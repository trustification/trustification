use crate::health::Check;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

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

impl Check for ProbeCheck {
    type Error = String;

    async fn run(&self) -> Result<(), Self::Error> {
        match self.state.as_ref().load(Ordering::Relaxed) {
            true => Ok(()),
            false => Err(self.error.clone()),
        }
    }
}
