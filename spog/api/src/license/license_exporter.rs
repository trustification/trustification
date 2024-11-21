use crate::license::license_scanner::LicenseScannerError;
use crate::license::SbomLicense;
use csv::WriterBuilder;
use flate2::write::{GzDecoder, GzEncoder};
use flate2::Compression;
use std::fmt::format;
use std::fs::File;
use std::io::{Cursor, Write};
use tar::Builder;

pub struct LicenseExporter {
    sbom_license: SbomLicense,
}

#[derive(Debug, thiserror::Error)]
pub enum LicenseExporterError {
    #[error("license scanner error: {0}")]
    LicenseExportError(#[from] LicenseScannerError),
    #[error("error from  csv write: {0}")]
    CsvError(#[from] csv::Error),
    #[error("error from  zip write: {0}")]
    // ZipError(#[from] zip::result::ZipError),
    // #[error("error from  csv inner error: {0}")]
    CsvIntoInnerError(#[from] csv::IntoInnerError<csv::Writer<Vec<u8>>>),
    #[error("error from  std io error: {0}")]
    StdError(#[from] std::io::Error),
}

impl LicenseExporter {
    pub fn new(sbom_license: SbomLicense) -> Self {
        LicenseExporter {
            sbom_license: sbom_license,
        }
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
        let sbom_csv = wtr_sbom.into_inner()?;
        let license_ref_csv = wtr_license_ref.into_inner()?;

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
mod tests {
    use crate::license::license_exporter::LicenseExporter;
    use crate::license::license_scanner::LicenseScanner;
    use sbom_walker::model::sbom::ParseAnyError;
    use sbom_walker::Sbom;
    use std::fs::File;
    use std::io::Write;
    use std::path::Path;

    fn load_sbom_file(path: impl AsRef<Path>) -> Result<Sbom, ParseAnyError> {
        let data = std::fs::read(&path).unwrap();
        Ok(Sbom::try_parse_any(&data)
            .unwrap_or_else(|_| panic!("failed to parse test data: {}", path.as_ref().display())))
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
        let mut file = File::create("/tmp/test.zip").unwrap();
        file.write_all(&export.generate().unwrap()).unwrap();
    }
}
