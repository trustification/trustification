use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::sync::Arc;
use time::OffsetDateTime;
use walker_extras::visitors::SendVisitor;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, serde::Deserialize, serde::Serialize)]
pub enum Phase {
    Retrieval,
    Validation,
    Upload,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Ord, PartialOrd, serde::Deserialize, serde::Serialize)]
pub enum Severity {
    Error,
    Warning,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Report {
    #[serde(with = "time::serde::iso8601")]
    pub start_date: OffsetDateTime,
    #[serde(with = "time::serde::iso8601")]
    pub end_date: OffsetDateTime,

    #[serde(default)]
    pub numer_of_items: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub messages: BTreeMap<Phase, BTreeMap<String, Vec<Message>>>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct Message {
    pub severity: Severity,
    pub message: String,
}

#[derive(Clone, Debug)]
pub struct ReportBuilder {
    report: Report,
}

impl ReportBuilder {
    pub fn new() -> Self {
        Self {
            report: Report {
                start_date: OffsetDateTime::now_utc(),
                end_date: OffsetDateTime::now_utc(),
                numer_of_items: 0,
                messages: Default::default(),
            },
        }
    }

    pub fn tick(&mut self) {
        self.report.numer_of_items += 1;
    }

    pub fn add_error(&mut self, phase: Phase, file: impl Into<String>, severity: Severity, message: impl Into<String>) {
        let file = file.into();
        let message = message.into();

        self.report
            .messages
            .entry(phase)
            .or_default()
            .entry(file)
            .or_default()
            .push(Message { severity, message });
    }

    pub fn build(mut self) -> Report {
        self.report.end_date = OffsetDateTime::now_utc();
        self.report
    }
}

impl Default for ReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ReportVisitor {
    pub report: Arc<Mutex<ReportBuilder>>,
    pub next: SendVisitor,
}

impl ReportVisitor {
    pub fn new(report: Arc<Mutex<ReportBuilder>>, next: SendVisitor) -> Self {
        Self { report, next }
    }
}

/// Fail a scanner process.
#[derive(Debug, thiserror::Error)]
pub enum ScannerError {
    /// A critical error occurred, we don't even have a report.
    #[error(transparent)]
    Critical(#[from] anyhow::Error),
    /// A normal error occurred, we did capture some information in the report.
    #[error("{err}")]
    Normal {
        #[source]
        err: anyhow::Error,
        report: Report,
    },
}

pub trait SplitScannerError {
    /// Split a [`ScannerError`] into a result and a report, unless it was critical.
    fn split(self) -> anyhow::Result<(Report, anyhow::Result<()>)>;
}

impl SplitScannerError for Result<Report, ScannerError> {
    fn split(self) -> anyhow::Result<(Report, anyhow::Result<()>)> {
        match self {
            Ok(report) => Ok((report, Ok(()))),
            Err(ScannerError::Normal { err, report }) => Ok((report, Err(err))),
            Err(ScannerError::Critical(err)) => Err(err),
        }
    }
}

/// Handle the report
pub async fn handle_report(report: Report) -> anyhow::Result<()> {
    // FIXME: this is a very simplistic version of handling the error
    log::info!("Import report: {report:#?}");
    Ok(())
}
