use super::{backtrace::backtrace, vex::collect_vex};
use crate::error::Error;
use crate::guac::service::GuacService;
use crate::server::AppState;
use crate::utils::spdx::find_purls;
use csaf::document::Category;
use csaf::Csaf;
use futures::{stream, StreamExt, TryStreamExt};
use guac::client::intrinsic::certify_vuln::CertifyVuln;
use packageurl::PackageUrl;
use spdx_rs::models::SPDX;
use spog_model::csaf::has_purl;
use spog_model::prelude::Remediation;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;
use std::str::FromStr;
use tracing::{info_span, instrument};
use trustification_auth::client::TokenProvider;

/// Analyze by purls
///
/// result(Ok):
///   map(CVE to array(PURL))
///   map(purl to parents(chain of purls))
///   total number of packages found
#[instrument(
    skip_all,
    fields(sbom_name=sbom.document_creation_information.document_name),
    err
)]
pub async fn analyze_spdx(
    state: &AppState,
    guac: &GuacService,
    token: &dyn TokenProvider,
    sbom: &SPDX,
) -> Result<AnalyzeOutcome, Error> {
    let purls = find_purls(sbom).collect::<BTreeMap<_, _>>();
    log::debug!("Extracted {} PURLs", purls.len());

    // turn strings into PURLs

    let purls = purls.keys().flat_map(|purl| match PackageUrl::from_str(purl) {
        Ok(purl) => Some(purl),
        Err(err) => {
            log::debug!("Failed to parse purl ({purl}): {err}");
            None
        }
    });

    let mut outcome = stream::iter(purls)
        .map(|purl| async move {
            let cert = guac.certify_vuln(purl.clone()).await?;
            Ok::<_, Error>((purl, cert))
        })
        .buffer_unordered(4)
        .and_then(|(purl, cert)| async move {
            let ids = cert
                .into_iter()
                .flat_map(|cert| cert.vulnerability.vulnerability_ids)
                .map(|id| id.vulnerability_id)
                .filter(|id| !id.is_empty())
                .collect::<Vec<_>>();

            let backtrace = if !ids.is_empty() {
                Some(backtrace(guac, &purl).await?.collect::<BTreeSet<_>>())
            } else {
                None
            };

            Ok::<_, Error>((purl, ids, backtrace))
        })
        .try_fold(
            AnalyzeOutcome::default(),
            |mut acc, (purl, ids, backtrace)| async move {
                for id in ids {
                    acc.cve_to_purl
                        .entry(id)
                        .or_default()
                        .insert(purl.to_string(), Default::default());
                }

                if let Some(backtrace) = backtrace {
                    acc.purl_to_backtrace.insert(purl.to_string(), backtrace);
                }

                acc.total += 1;

                Ok(acc)
            },
        )
        .await?;

    // get all relevant VEX documents

    let vex = collect_vex(state, token, outcome.cve_to_purl.keys()).await?;

    // fill in the remediations

    info_span!("scrape_remediations").in_scope(|| {
        let mut count = 0;
        for (cve, map) in &mut outcome.cve_to_purl {
            for (purl, rem) in map {
                let rems = scrape_remediations(cve, purl, &vex);
                if !rems.is_empty() {
                    log::debug!("Remediations for {cve} / {purl}: {rems:?}");
                }
                count += rems.len();
                rem.extend(rems);
            }
        }
        log::debug!("Found {count} remediations");
    });

    // done

    log::debug!("Processed {} packages", outcome.total);

    Ok(outcome)
}

#[derive(Default)]
pub struct AnalyzeOutcome {
    // CVE to PURLs to remediations
    cve_to_purl: BTreeMap<String, BTreeMap<String, Vec<Remediation>>>,
    // PURL to backtrace
    purl_to_backtrace: BTreeMap<String, BTreeSet<Vec<String>>>,
    // total number of PURLs
    total: usize,
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
        let csaf = include_bytes!("../../../../example-data/cve-2023-22998.json");
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
