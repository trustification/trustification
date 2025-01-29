use crate::license::{ExtractedLicensingInfos, SbomLicense};
use crate::utils::get_sanitize_filename;
use actix_web::body::BoxBody;
use actix_web::http::header::ContentType;
use actix_web::{HttpResponse, ResponseError};
use csv::WriterBuilder;
use flate2::write::GzEncoder;
use flate2::Compression;
use http::StatusCode;
use tar::Builder;
use trustification_common::error::ErrorInformation;

extern crate sanitize_filename;

pub struct LicenseExporter {
    sbom_license: SbomLicense,
    extracted_licensing_infos: Vec<ExtractedLicensingInfos>,
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
    pub fn new(sbom_license: SbomLicense, extracted_licensing_infos: Vec<ExtractedLicensingInfos>) -> Self {
        LicenseExporter {
            sbom_license,
            extracted_licensing_infos,
        }
    }

    pub fn generate(&self) -> Result<Vec<u8>, LicenseExporterError> {
        let mut wtr_sbom = WriterBuilder::new()
            .delimiter(b'\t')
            .quote_style(csv::QuoteStyle::Always)
            .has_headers(true) // Set delimiter to tab
            .from_writer(vec![]);

        let mut wtr_license_ref = WriterBuilder::new()
            .delimiter(b'\t')
            .quote_style(csv::QuoteStyle::Always)
            .has_headers(true)
            .from_writer(vec![]);
        wtr_license_ref.write_record(["licenseId", "name", "extracted text", "comment"])?;
        wtr_sbom.write_record([
            "name",
            "namespace",
            "group",
            "version",
            "package reference",
            "license id",
            "license name",
            "license expression",
            "alternate package reference",
        ])?;

        for extracted_licensing_info in &self.extracted_licensing_infos {
            wtr_license_ref.write_record([
                extracted_licensing_info.license_id.as_str(),
                extracted_licensing_info.name.as_str(),
                extracted_licensing_info.extracted_text.as_str(),
                extracted_licensing_info.comment.as_str(),
            ])?;
        }

        for pl in &self.sbom_license.packages {
            let alternate_package_reference = pl
                .other_reference
                .iter()
                .map(|reference| reference.as_str())
                .collect::<Vec<_>>()
                .join("\n");

            let spdx_licenses = pl
                .spdx_licenses
                .iter()
                .map(|reference| reference.as_str())
                .collect::<Vec<_>>()
                .join("\n");

            wtr_sbom.write_record([
                &pl.name,
                &self.sbom_license.sbom_namespace,
                &self.sbom_license.component_group,
                &self.sbom_license.component_version,
                &pl.purl,
                &spdx_licenses,
                &pl.license_name,
                &pl.license_text,
                alternate_package_reference.as_str(),
            ])?;
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
            archive.append_data(
                &mut header,
                format!(
                    "{}_sbom_licenses.csv",
                    &get_sanitize_filename(String::from(&self.sbom_license.sbom_name))
                ),
                &*sbom_csv,
            )?;

            let mut header = tar::Header::new_gnu();
            header.set_size(license_ref_csv.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            archive.append_data(
                &mut header,
                format!(
                    "{}_license_ref.csv",
                    &get_sanitize_filename(String::from(&self.sbom_license.sbom_name))
                ),
                &*license_ref_csv,
            )?;

            archive.finish()?;
        }
        Ok(compressed_data)
    }
}

#[cfg(test)]
mod tests {
    use crate::license::license_exporter::LicenseExporter;
    use crate::license::license_scanner::LicenseScanner;
    use crate::utils::get_sanitize_filename;
    use bombastic_model::data::SBOM;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    fn load_sbom_file(path: impl AsRef<Path>) -> Result<SBOM, anyhow::Error> {
        let data = std::fs::read(&path).unwrap_or_else(|e| panic!("read file failed {:?}", e));
        Ok(SBOM::parse(&data).unwrap_or_else(|_| panic!("failed to parse test data: {}", path.as_ref().display())))
    }

    #[tokio::test]
    async fn test_get_sanitize_filename() {
        let sbom_name =
            "/var/lib/containers/storage/vfs/dir/0efa662cc0258b94827838a8c160142b92fefb10b165b204705d9903b3286e89";
        let result = get_sanitize_filename(sbom_name.to_string());
        assert!(!result.contains('/'));
    }

    #[tokio::test]
    async fn is_works_cydx() {
        let sbom =
            load_sbom_file("../test-data/application.cdx.json").unwrap_or_else(|_| panic!("failed to parse test data"));

        let license_scanner = LicenseScanner::new(sbom);

        let (sbom_licenses, extracted_licensing_info) = license_scanner
            .scanner()
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        let export = LicenseExporter::new(sbom_licenses, extracted_licensing_info);
        let mut file =
            File::create("/tmp/application.cdx_licenses.tar.gz").unwrap_or_else(|_| panic!("create file failed"));
        file.write_all(&export.generate().unwrap_or_else(|_| panic!("generate failed")))
            .unwrap_or_else(|_| panic!("write file failed"));
    }

    #[tokio::test]
    async fn is_works_cydx_with_cpe() {
        let sbom = load_sbom_file("../test-data/tc_1730_license_escape.json")
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        let license_scanner = LicenseScanner::new(sbom);

        let (sbom_licenses, extracted_licensing_info) = license_scanner
            .scanner()
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        let export = LicenseExporter::new(sbom_licenses, extracted_licensing_info);
        let mut file =
            File::create("/tmp/tc_1730_license_escape.tar.gz").unwrap_or_else(|_| panic!("create file failed"));
        file.write_all(&export.generate().unwrap_or_else(|_| panic!("generate failed")))
            .unwrap_or_else(|_| panic!("write file failed"));
    }

    #[tokio::test]
    async fn is_works_spdx() {
        let sbom = load_sbom_file("../test-data/mtv-2.6.json").unwrap_or_else(|_| panic!("failed to parse test data"));

        let license_scanner = LicenseScanner::new(sbom);

        let (sbom_licenses, extracted_licensing_info) = license_scanner
            .scanner()
            .unwrap_or_else(|_| panic!("failed to parse test data"));

        let export = LicenseExporter::new(sbom_licenses, extracted_licensing_info);
        let mut file = File::create("/tmp/mtv-2.6.tar.gz").unwrap_or_else(|_| panic!("create file failed"));
        file.write_all(&export.generate().unwrap_or_else(|_| panic!("generate failed")))
            .unwrap_or_else(|_| panic!("write file failed"));
    }
}
