use crate::health::Check;
use async_trait::async_trait;

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
