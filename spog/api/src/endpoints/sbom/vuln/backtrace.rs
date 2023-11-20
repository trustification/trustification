use super::Error;
use crate::service::guac::GuacService;
use names::Generator;
use packageurl::PackageUrl;
use rand::Rng;
use spog_model::prelude::Backtrace;
use tracing::instrument;

/// take a PURL, a retrieve all paths towards the main entry point of its SBOM
// FIXME: This needs to be implemented
#[instrument(skip(_guac), err)]
pub async fn backtrace<'a>(
    _guac: &GuacService,
    _purl: &'a PackageUrl<'a>,
) -> Result<impl Iterator<Item = Backtrace> + 'a, Error> {
    let mut rng = rand::thread_rng();
    let mut names = Generator::default();

    // create some mock data
    let mut result = vec![];

    for _ in 0..rng.gen_range(0..5) {
        let mut trace = vec![];
        for _ in 0..rng.gen_range(1..5) {
            trace.push(
                PackageUrl::new("mock", names.next().unwrap_or_else(|| "mock".to_string()))
                    .map(|purl| purl.to_string())
                    .unwrap_or_else(|_| "pkg://mock/failed".to_string())
                    .to_string(),
            );
        }
        result.push(Backtrace(trace));
    }

    Ok(result.into_iter())
}
