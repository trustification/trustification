use crate::license::SbomLicense;
use actix_web::body::BoxBody;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, ResponseError};
use csv::WriterBuilder;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::StatusCode;
use tar::Builder;
use trustification_common::error::ErrorInformation;

pub struct LicenseExporter {
    sbom_license: SbomLicense,
}

#[derive(Debug, thiserror::Error)]
pub enum LicenseExporterError {
    #[error("error from  csv write: {0}")]
    CsvError(#[from] csv::Error),
    #[error("error from  csv inner error: {0}")]
    CsvIntoInnerError(String),
    #[error("error from  std io error: {0}")]
    Io(#[from] std::io::Error),
}

impl ResponseError for LicenseExporterError {
    fn status_code(&self) -> StatusCode {
        match self {
            LicenseExporterError::CsvError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            LicenseExporterError::CsvIntoInnerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            LicenseExporterError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn error_response(&self) -> HttpResponse<BoxBody> {
        let mut res = HttpResponse::build(self.status_code());
        res.insert_header(ContentType::json());

        match self {
            LicenseExporterError::CsvError(csv_error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: format!("{}", csv_error),
                details: csv_error.to_string(),
            }),

            LicenseExporterError::CsvIntoInnerError(csv_into_inner_error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: csv_into_inner_error.to_string(),
                details: csv_into_inner_error.to_string(),
            }),

            LicenseExporterError::Io(std_error) => res.json(ErrorInformation {
                error: format!("{}", self.status_code()),
                message: format!("{}", std_error),
                details: std_error.to_string(),
            }),
        }
    }
}

impl LicenseExporter {
    pub fn new(sbom_license: SbomLicense) -> Self {
        LicenseExporter { sbom_license }
    }

    pub fn generate(&self) -> Result<Vec<u8>, LicenseExporterError> {
        let mut wtr_sbom = WriterBuilder::new()
            .delimiter(b'\t')
            .has_headers(true) // Set delimiter to tab
            .from_writer(vec![]);
        wtr_sbom.write_record([
            "name",
            "package_name",
            "package_namespace",
            "package_version",
            "referenceLocator",
            "licenceDeclared: license_ID",
            "licenceDeclared: license_name",
        ])?;

        let mut wtr_license_ref = WriterBuilder::new()
            .delimiter(b'\t')
            .has_headers(true)
            .from_writer(vec![]);
        wtr_license_ref.write_record(["licenseId", "name", "extracted text", "comment"])?;

        wtr_sbom.write_record([
            &self.sbom_license.sbom_name,
            "            ",
            "                ",
            "              ",
            "               ",
            "                         ",
            "                           ",
        ])?;

        for pl in &self.sbom_license.packages {
            wtr_sbom.write_record([
                "",
                &pl.purl_name,
                &pl.purl_namespace,
                &pl.version.as_ref().map_or(String::new(), |v| v.to_string()),
                &pl.purl,
                "",
                "",
            ])?;

            for l in &pl.licenses {
                wtr_sbom.write_record([
                    "    ",
                    "            ",
                    "                ",
                    "              ",
                    "                    ",
                    l.license_id.as_str(),
                    l.name.as_str(),
                ])?;
                if l.is_license_ref {
                    wtr_license_ref.write_record([
                        l.license_id.as_str(),
                        l.name.as_str(),
                        l.license_text.as_str(),
                        l.license_comment.as_str(),
                    ])?;
                }
            }
        }
        let sbom_csv = wtr_sbom
            .into_inner()
            .map_err(|err| LicenseExporterError::CsvIntoInnerError(format!("csv into inner error: {}", err)))?;
        let license_ref_csv = wtr_license_ref
            .into_inner()
            .map_err(|err| LicenseExporterError::CsvIntoInnerError(format!("csv into inner error: {}", err)))?;

        let mut compressed_data = Vec::new();
        {
            let encoder = GzEncoder::new(&mut compressed_data, Compression::default());

            let mut archive = Builder::new(encoder);

            let mut header = tar::Header::new_gnu();
            header.set_size(sbom_csv.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, "sbom_licenses.csv", &*sbom_csv)?;

            let mut header = tar::Header::new_gnu();
            header.set_size(license_ref_csv.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(&mut header, "license_ref.csv", &*license_ref_csv)?;

            archive.finish()?;
        }
        Ok(compressed_data)
    }
}

#[cfg(test)]
mod tests {
    use crate::license::license_exporter::LicenseExporter;
    use crate::license::license_scanner::LicenseScanner;
    use bombastic_model::data::SBOM;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    fn load_sbom_file(path: impl AsRef<Path>) -> Result<SBOM, anyhow::Error> {
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read file failed {:?}", e));
        Ok(SBOM::parse(&data).unwrap_or_else(|_| panic!("failed to parse test data: {}", path.as_ref().display())))
    }

    #[tokio::test]
    async fn is_works() {
        let sbom =
            load_sbom_file("../test-data/rhel-7.9.z.json").unwrap_or_else(|_| panic!("failed to parse test data"));

        let license_scanner = LicenseScanner::new(sbom);

        let sbom_licenses = license_scanner
            .scanner()
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        let export = LicenseExporter::new(sbom_licenses);
        let mut file = File::create("/tmp/test.zip").unwrap_or_else(|_| panic!("create file failed"));
        file.write_all(&export.generate().unwrap_or_else(|_| panic!("generate failed")))
            .unwrap_or_else(|_| panic!("write file failed"));
    }
}
