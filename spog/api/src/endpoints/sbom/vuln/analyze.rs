use super::AppState;
use super::{backtrace::backtrace, vex::collect_vex};
use crate::error::Error;
use crate::service::guac::{GuacSbomIdentifier, GuacService};
use csaf::document::Category;
use csaf::Csaf;
use futures::{stream, StreamExt, TryStreamExt};
use guac::client::intrinsic::vuln_metadata::VulnerabilityScoreType;
use packageurl::PackageUrl;
use spdx_rs::models::PackageInformation;
use spog_model::csaf::has_purl;
use spog_model::prelude::{Backtrace, Remediation};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::str::FromStr;
use tracing::{info_span, instrument, Instrument};
use trustification_auth::client::TokenProvider;

#[derive(Clone, Debug, Default, Hash, Ord, PartialOrd, Eq, PartialEq)]
struct GuacVulnId(String);

#[derive(Clone, Debug)]
pub struct Score {
    pub source: String,
    pub r#type: VulnerabilityScoreType,
    pub value: f32,
}

#[derive(Default)]
pub struct AnalyzeOutcome {
    // CVE to PURLs to remediations
    pub cve_to_purl: BTreeMap<String, BTreeMap<String, Vec<Remediation>>>,
    // PURL to backtrace
    pub purl_to_backtrace: BTreeMap<String, BTreeSet<Backtrace>>,
}

/// Analyze by purls
///
/// result(Ok):
///   map(CVE to array(PURL))
///   map(purl to parents(chain of purls))
///   total number of packages found
#[instrument(skip(state, guac, token), err)]
pub async fn analyze_spdx(
    state: &AppState,
    guac: &GuacService,
    token: &dyn TokenProvider,
    main: &PackageInformation,
    offset: Option<i64>,
    limit: Option<i64>,
) -> Result<AnalyzeOutcome, Error> {
    let version = match &main.package_version {
        Some(version) => version,
        None => {
            return Err(Error::Generic(
                "SBOM's main component is missing the version".to_string(),
            ))
        }
    };

    // find vulnerabilities

    let cve_to_purl = guac
        .find_vulnerability(GuacSbomIdentifier {
            name: &main.package_name,
            version,
        }, offset, limit)
        .await?;

    // collect the backtraces

    let purl_to_backtrace = async {
        stream::iter(
            cve_to_purl
                .values()
                .flatten()
                .filter_map(|purl| PackageUrl::from_str(purl).ok()),
        )
        .map(|purl| async move {
            let backtraces = backtrace(guac, &purl).await?.collect::<BTreeSet<_>>();
            Ok::<_, Error>((purl.to_string(), backtraces))
        })
        .buffer_unordered(4)
        .try_collect()
        .await
    }
    .instrument(info_span!("collect backtraces"))
    .await?;

    // get all relevant VEX documents

    let vex = collect_vex(state, token, cve_to_purl.keys()).await?;

    // fill in the remediations

    let cve_to_purl = info_span!("scrape_remediations").in_scope(|| {
        let mut count = 0;

        let result = cve_to_purl
            .into_iter()
            .map(|(cve, purls)| {
                let purls = purls
                    .into_iter()
                    .map(|purl| {
                        let rem = scrape_remediations(&cve, &purl, &vex);
                        count += rem.len();

                        (purl, rem)
                    })
                    .collect::<BTreeMap<String, Vec<Remediation>>>();
                (cve, purls)
            })
            .collect();

        log::debug!("Found {count} remediations");

        result
    });

    // done

    Ok(AnalyzeOutcome {
        cve_to_purl,
        purl_to_backtrace,
    })
}

/// from a set of relevant VEXes, fetch the matching remediations for this PURL
fn scrape_remediations(id: &str, purl: &str, vex: &HashMap<String, Vec<Rc<Csaf>>>) -> Vec<Remediation> {
    let mut result = vec![];

    // iterate over all documents
    for vex in vex.get(id).iter().flat_map(|v| *v) {
        if vex.document.category != Category::Vex {
            continue;
        }

        // iterate over all vulnerabilities of the document
        for v in vex
            .vulnerabilities
            .iter()
            .flatten()
            .filter(|v| v.cve.as_deref() == Some(id))
        {
            // now convert all the remediations
            for r in v.remediations.iter().flatten() {
                // only add remediations matching the purl
                if !has_purl(vex, &r.product_ids, purl) {
                    continue;
                }

                result.push(Remediation {
                    details: r.details.clone(),
                })
            }
        }
    }

    result
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_scrape_remediations() {
        let csaf = include_bytes!("../../../../../example-data/cve-2023-22998.json");
        let csaf: Csaf = serde_json::from_slice(csaf).unwrap();

        let mut vex = HashMap::new();
        vex.insert("CVE-2023-22998".to_string(), vec![Rc::new(csaf)]);
        let rem = scrape_remediations(
            "CVE-2023-22998",
            "pkg:rpm/redhat/kernel-rt-modules-extra@5.14.0-284.11.1.rt14.296.el9_2?arch=x86_64",
            &vex,
        );

        assert_eq!(rem, vec![Remediation{
            details: "Before applying this update, make sure all previously released errata\nrelevant to your system have been applied.\n\nFor details on how to apply this update, refer to:\n\nhttps://access.redhat.com/articles/11258".to_string()
        }]);
    }
}
