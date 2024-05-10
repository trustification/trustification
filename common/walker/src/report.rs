use parking_lot::Mutex;
use serde_json::to_string;
use std::{collections::BTreeMap, env, ffi::OsString, fs, fs::File, io::Write, sync::Arc};
use tera::{Context, Tera};
use time::macros::format_description;
use time::OffsetDateTime;
use walker_extras::visitors::SendVisitor;

const DEFAULT_REPORT_OUTPUT_PATH: &str = "/tmp/share/reports";

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

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub enum ReportType {
    SBOM(String),
    VEX(String),
}
/// Handle the report
pub async fn handle_report(report: Report, report_type: ReportType) -> anyhow::Result<()> {
    let path = env::var_os("REPORT_PATH").unwrap_or_else(|| OsString::from(DEFAULT_REPORT_OUTPUT_PATH));
    let path = path.to_str().unwrap_or(DEFAULT_REPORT_OUTPUT_PATH).to_string();

    let report_type_string = match report_type {
        ReportType::SBOM(sbom) => sbom,
        ReportType::VEX(vex) => vex,
    };

    ///Generate a report in html format.
    let template_content = include_str!("../templates/report.html");
    let mut tera = Tera::default();
    tera.add_raw_template("report.html", template_content)?;

    let mut context = Context::new();
    let current_time = OffsetDateTime::now_utc();
    context.insert("report", &report);
    context.insert("type", &report_type_string);
    context.insert("current_time", &current_time);

    let format = format_description!("[year]-[month]-[day].[hour].[minute].[second]");
    let formatted_time = current_time.clone().format(&format)?;
    match tera.render("report.html", &context) {
        Ok(rendered_html) => {
            let out_put_html_path = format!("{path}/{report_type_string}/html/report-{formatted_time}.html");
            if let Some(parent) = std::path::Path::new(&out_put_html_path).parent() {
                fs::create_dir_all(parent)?;
            }
            let mut file = match File::create(out_put_html_path.clone()) {
                Ok(file) => file,
                Err(e) => {
                    log::warn!(" The {} created failed. {:?}", out_put_html_path.clone(), e);
                    return Err(e.into());
                }
            };

            let _ = writeln!(file, "{}", rendered_html);
            let _ = file.sync_all();
        }
        Err(e) => {
            log::warn!(
                "There was an error generating the page, please check your files. {:?}",
                e
            )
        }
    }

    ///Generate a report in JSON format.
    let out_put_json_path = format!("{path}/{report_type_string}/json/report-{formatted_time}.json");
    if let Some(parent) = std::path::Path::new(&out_put_json_path).parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = match File::create(out_put_json_path.clone()) {
        Ok(file) => file,
        Err(e) => {
            log::warn!(" The {} created failed. {:?}", out_put_json_path.clone(), e);
            return Err(e.into());
        }
    };

    let _ = writeln!(file, "{:?}", to_string(&report).unwrap())?;
    let _ = file.sync_all();
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::report::{handle_report, Message, Phase, ReportBuilder, ReportType, Severity};

    #[tokio::test]
    async fn test_handle_report() {
        let mut report = ReportBuilder::new();
        report
            .report
            .messages
            .entry(Phase::Validation)
            .or_default()
            .entry("test1".to_string())
            .or_default()
            .push(Message {
                severity: Severity::Error,
                message: "test1 message one".to_string(),
            });

        report
            .report
            .messages
            .entry(Phase::Upload)
            .or_default()
            .entry("test2".to_string())
            .or_default()
            .push(Message {
                severity: Severity::Error,
                message: "test2 message two".to_string(),
            });

        let rs = handle_report(report.report, ReportType::SBOM("Sbom".to_string())).await;
        match rs {
            Ok(_rt) => assert_eq!(true, true),
            Err(_e) => assert_eq!(true, false),
        };
    }
}
