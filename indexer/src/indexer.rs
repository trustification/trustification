use bombastic_event_bus::EventBus;
use bombastic_index::Index;

pub async fn run<T: AsRef<std::path::Path>, E: EventBus>(index: T, events: E) -> Result<(), anyhow::Error> {
    let index = Index::new(index)?;
    Ok(())
}
