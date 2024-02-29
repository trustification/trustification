use async_trait::async_trait;
use parking_lot::Mutex;
use sbom_walker::validation::ValidationError;
use std::collections::BTreeMap;
use std::sync::Arc;
use time::OffsetDateTime;
use walker_common::utils::url::Urlify;
use walker_extras::visitors::{SendValidatedSbomError, SendVisitor};

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

pub struct ReportVisitor {
    report: Arc<Mutex<ReportBuilder>>,
    next: SendVisitor,
}

impl ReportVisitor {
    pub fn new(report: Arc<Mutex<ReportBuilder>>, next: SendVisitor) -> Self {
        Self { report, next }
    }
}

#[async_trait(?Send)]
impl sbom_walker::validation::ValidatedVisitor for ReportVisitor {
    type Error = <SendVisitor as sbom_walker::validation::ValidatedVisitor>::Error;
    type Context = <SendVisitor as sbom_walker::validation::ValidatedVisitor>::Context;

    async fn visit_context(
        &self,
        context: &sbom_walker::validation::ValidationContext,
    ) -> Result<Self::Context, Self::Error> {
        self.next.visit_context(context).await
    }

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        result: Result<sbom_walker::validation::ValidatedSbom, sbom_walker::validation::ValidationError>,
    ) -> Result<(), Self::Error> {
        let file = result.url().to_string();

        self.report.lock().tick();

        let result = self.next.visit_sbom(context, result).await;

        if let Err(err) = &result {
            match err {
                SendValidatedSbomError::Validation(ValidationError::Retrieval(err)) => {
                    self.report.lock().add_error(
                        Phase::Retrieval,
                        file,
                        Severity::Error,
                        format!("retrieval of document: {err}"),
                    );
                }
                SendValidatedSbomError::Validation(ValidationError::DigestMismatch { expected, actual, .. }) => {
                    self.report.lock().add_error(
                        Phase::Validation,
                        file,
                        Severity::Error,
                        format!("digest mismatch - expected: {expected}, actual: {actual}"),
                    );
                }
                SendValidatedSbomError::Validation(ValidationError::Signature { error, .. }) => {
                    self.report.lock().add_error(
                        Phase::Validation,
                        file,
                        Severity::Error,
                        format!("unable to verify signature: {error}"),
                    );
                }
                SendValidatedSbomError::Store(err) => {
                    self.report
                        .lock()
                        .add_error(Phase::Upload, file, Severity::Error, format!("upload failed: {err}"));
                }
            }
        }

        result
    }
}
