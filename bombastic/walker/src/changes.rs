use anyhow::Result;
use chrono::{DateTime, Utc};
use csv;
use reqwest::Url;
use std::collections::HashMap;
use std::io::Write;

use serde::Deserialize;

#[derive(Debug, Deserialize, Eq, PartialEq)]
struct ChangeRow {
    path: String,
    last_change: DateTime<Utc>,
}

pub struct ChangeTracker {
    address: Url,
    store: HashMap<String, DateTime<Utc>>,
}

impl ChangeTracker {
    pub fn new(address: Url) -> ChangeTracker {
        ChangeTracker {
            address,
            store: HashMap::new(),
        }
    }

    pub async fn update(&mut self) -> Result<Vec<String>> {
        let new_change_file = Self::download_changesfile(&self.address).await?;
        let new_store = Self::read_csv(new_change_file).await?;

        let mut to_update = Vec::new();
        for new_entry in &new_store {
            if let Some(entry) = self.store.get(new_entry.0) {
                if entry < &new_entry.1 {
                    to_update.push(new_entry.0.clone())
                }
            } else {
                to_update.push(new_entry.0.clone())
            }
        }
        self.store = new_store;

        Ok(to_update)
    }

    async fn read_csv(content: TextBody) -> Result<HashMap<String, DateTime<Utc>>> {
        let mut store = HashMap::new();

        let mut rdr = csv::ReaderBuilder::new().has_headers(false).from_reader(content);

        for result in rdr.deserialize() {
            let record: ChangeRow = result.unwrap();
            store.insert(record.path, record.last_change);
        }

        Ok(store)
    }

    async fn download_changesfile(address: &Url) -> Result<TextBody> {
        let body = reqwest::get(address.clone()).await?.text().await?;

        Ok(TextBody::from(body))
    }
}

struct TextBody {
    body: Vec<String>,
    index: usize,
}

impl std::io::Read for TextBody {
    fn read(&mut self, mut buf: &mut [u8]) -> std::io::Result<usize> {
        if self.index < self.body.len() {
            let line = self.body.get(self.index).unwrap();
            let size = line.len();
            buf.write(line.as_bytes())?;

            self.index += 1;
            Ok(size)
        } else {
            return Ok(0);
        }
    }
}

impl From<String> for TextBody {
    fn from(value: String) -> Self {
        TextBody {
            body: value.split_inclusive("\n").map(|s| s.to_string()).collect(),
            index: 0,
        }
    }
}
