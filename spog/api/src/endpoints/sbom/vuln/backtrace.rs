use super::Error;
use crate::service::guac::GuacService;
use packageurl::PackageUrl;
use spog_model::prelude::Backtrace;
use tracing::instrument;

/// take a PURL, a retrieve all paths towards the main entry point of its SBOM
#[instrument(skip(_guac), err)]
pub async fn backtrace<'a>(
    _guac: &GuacService,
    _purl: &'a PackageUrl<'a>,
) -> Result<impl Iterator<Item = Backtrace> + 'a, Error> {
    let result = vec![];

    // FIXME: This needs to be implemented

    Ok(result.into_iter())
}
