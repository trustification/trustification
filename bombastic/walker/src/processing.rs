use async_trait::async_trait;
use bytes::Bytes;
use bzip2::Compression;
use sbom_walker::model::sbom::ParserKind;
use sbom_walker::validation::{ValidatedSbom, ValidatedVisitor, ValidationContext, ValidationError};
use sbom_walker::Sbom;
use serde_json::Value;
use std::io::Write;
use walker_common::compression::decompress_opt;

pub struct ProcessVisitor<V> {
    /// if processing is enabled
    pub enabled: bool,
    /// then next visitor to call
    pub next: V,
}

#[async_trait(?Send)]
impl<V> ValidatedVisitor for ProcessVisitor<V>
where
    V: ValidatedVisitor,
    V::Error: std::error::Error + Send + Sync + 'static,
{
    type Error = anyhow::Error;
    type Context = V::Context;

    async fn visit_context(&self, context: &ValidationContext) -> Result<Self::Context, Self::Error> {
        Ok(self.next.visit_context(context).await?)
    }

    async fn visit_sbom(
        &self,
        context: &Self::Context,
        result: Result<ValidatedSbom, ValidationError>,
    ) -> Result<(), Self::Error> {
        match self.enabled {
            true => {
                let sbom = match result {
                    Ok(doc) => {
                        log::info!("Processing: {}", doc.url.path());
                        doc
                    }
                    Err(err) => {
                        log::info!("Failed ({}): {}", err.url().path(), err);
                        self.next.visit_sbom(context, Err(err)).await?;
                        return Ok(());
                    }
                };

                let (outcome, mut sbom) =
                    tokio::task::spawn_blocking(move || (process(sbom.data.clone(), sbom.url.path()), sbom)).await?;

                match outcome {
                    Err(err) => log::warn!("Failed processing, moving on: {err}"),
                    Ok(Some(data)) => {
                        log::info!("Got replacement, apply and store");
                        sbom.data = data;
                    }
                    Ok(None) => {
                        // keep current
                    }
                }

                self.next.visit_sbom(context, Ok(sbom)).await?;
            }
            false => {
                self.next.visit_sbom(context, result).await?;
            }
        }

        Ok(())
    }
}

fn process(data: Bytes, name: &str) -> anyhow::Result<Option<Bytes>> {
    let (data, compressed) = match decompress_opt(&data, name).transpose()? {
        Some(data) => (data, true),
        None => (data, false),
    };

    if let Err(err) = Sbom::try_parse_any(&data) {
        log::info!("Failed to parse, trying to understand why: {err}");

        if let Some((_, err)) = err.0.iter().find(|(kind, _err)| *kind == ParserKind::Spdx23Json) {
            log::info!("Failed to parse SPDX SBOM, try correcting license: {err}");

            return match serde_json::from_slice::<Value>(&data) {
                Err(err) => {
                    log::warn!("Failed to parse as JSON, there's nothing we can do: {err}");
                    return Ok(None);
                }
                Ok(json) => {
                    let (json, changed) = fix_license(json);
                    match changed {
                        true => {
                            let mut data = serde_json::to_vec(&json)?;
                            if compressed {
                                data = compress(&data)?;
                            }
                            Ok(Some(data.into()))
                        }
                        false => Ok(None),
                    }
                }
            };
        }
    }

    Ok(None)
}

fn compress(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::<u8>::new();
    {
        let mut encoder = bzip2::write::BzEncoder::new(&mut out, Compression::default());
        encoder.write_all(data)?;
    }
    Ok(out)
}

fn fix_license(mut json: Value) -> (Value, bool) {
    let mut changed = false;
    if let Some(packages) = json["packages"].as_array_mut() {
        for package in packages {
            if let Some(declared) = package["licenseDeclared"].as_str() {
                if let Err(err) = spdx_expression::SpdxExpression::parse(declared) {
                    log::warn!("Replacing faulty SPDX license expression with NOASSERTION: {err}");
                    package["licenseDeclared"] = "NOASSERTION".into();
                    changed = true;
                }
            }
        }
    }

    (json, changed)
}
