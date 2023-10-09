use crate::data::Cve;
use std::ffi::OsStr;
use std::fs::File;
use std::io::BufReader;
use std::path::Path;

pub struct Indexer {}

impl Indexer {
    pub fn new() -> Self {
        Self {}
    }

    pub fn add(&mut self, path: &Path) -> anyhow::Result<()> {
        let cve = match path.file_name().and_then(OsStr::to_str) {
            Some(name) => name,
            None => return Ok(()),
        };

        log::info!("{}: {}", cve, path.display());

        let cve: Cve = serde_json::from_reader(BufReader::new(File::open(&path)?))?;

        Ok(())
    }
}
