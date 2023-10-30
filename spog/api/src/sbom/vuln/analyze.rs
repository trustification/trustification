use super::{backtrace::backtrace, vex::collect_vex};
use crate::error::Error;
use crate::guac::service::GuacService;
use crate::server::AppState;
use crate::utils::spdx::find_purls;
use csaf::document::Category;
use csaf::Csaf;
use futures::{stream, StreamExt, TryStreamExt};
use guac::client::intrinsic::vuln_metadata::VulnerabilityScoreType;
use packageurl::PackageUrl;
use spdx_rs::models::SPDX;
use spog_model::csaf::has_purl;
use spog_model::prelude::Remediation;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use std::str::FromStr;
use tracing::{info_span, instrument};
use trustification_auth::client::TokenProvider;

const PARALLEL_GUAC: usize = 4;

#[derive(Clone, Debug, Default)]
struct IntermediateResult {
    // guac vuln ID to PURLs to remediations
    vuln_to_purl: HashMap<GuacVulnId, BTreeMap<String, Vec<Remediation>>>,
    // PURL to backtrace
    purl_to_backtrace: BTreeMap<String, BTreeSet<Vec<String>>>,
    // total number of PURLs
    total: usize,
}

#[derive(Clone, Debug, Default, Hash, Ord, PartialOrd, Eq, PartialEq)]
struct GuacVulnId(String);

#[derive(Clone, Debug)]
pub struct Score {
    pub source: String,
    pub r#type: VulnerabilityScoreType,
    pub value: f32,
}

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

    let IntermediateResult {
        vuln_to_purl,
        purl_to_backtrace,
        total,
    } = stream::iter(purls)
        .map(|purl| async move {
            let cert = guac.certify_vuln(purl.clone()).await?;
            Ok::<_, Error>((purl, cert))
        })
        .buffer_unordered(PARALLEL_GUAC)
        .and_then(|(purl, cert)| async move {
            // extract vuln IDs from certifications
            let ids = cert
                .into_iter()
                .map(|cert| cert.vulnerability.id)
                .map(GuacVulnId)
                .collect::<Vec<_>>();

            let backtrace = if !ids.is_empty() {
                Some(backtrace(guac, &purl).await?.collect::<BTreeSet<_>>())
            } else {
                None
            };

            Ok::<_, Error>((purl, ids, backtrace))
        })
        .try_fold(
            IntermediateResult::default(),
            |mut acc, (purl, ids, backtrace)| async move {
                for id in ids {
                    acc.vuln_to_purl
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

    // resolve IDs

    let cve_to_purl = stream::iter(vuln_to_purl)
        .map(|(vuln, purls)| async move {
            let scores = guac
                .vuln_meta(vuln.0.clone())
                .await?
                .into_iter()
                .map(|meta| Score {
                    source: meta.origin,
                    r#type: meta.score_type,
                    value: meta.score_value as f32,
                })
                .collect::<Vec<_>>();
            let aliases = guac
                .vuln_aliases(vuln.0)
                .await?
                .into_iter()
                .flat_map(|alias| alias.vulnerabilities)
                .map(|alias| alias.id.to_uppercase())
                .filter(|id| id.starts_with("CVE-"))
                .collect::<HashSet<_>>();

            Ok::<_, Error>((aliases, scores, purls))
        })
        .buffer_unordered(PARALLEL_GUAC)
        .try_fold(BTreeMap::new(), |mut acc, (aliases, scores, purls)| async move {
            let details = VulnerabilityDetails { scores, purls };

            let mut aliases = aliases.into_iter();
            let last = aliases.next();

            for alias in aliases {
                acc.insert(alias, details.clone());
            }

            // avoid one clone
            if let Some(last) = last {
                acc.insert(last, details);
            }

            Ok(acc)
        })
        .await?;

    let mut outcome = AnalyzeOutcome {
        cve_to_purl,
        purl_to_backtrace,
        total,
    };

    // get all relevant VEX documents

    let vex = collect_vex(state, token, outcome.cve_to_purl.keys()).await?;

    // fill in the remediations

    info_span!("scrape_remediations").in_scope(|| {
        let mut count = 0;
        for (cve, map) in &mut outcome.cve_to_purl {
            for (purl, rem) in &mut map.purls {
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

#[derive(Clone, Debug)]
pub struct VulnerabilityDetails {
    pub scores: Vec<Score>,
    pub purls: BTreeMap<String, Vec<Remediation>>,
}

#[derive(Default)]
pub struct AnalyzeOutcome {
    // CVE to PURLs to remediations
    pub cve_to_purl: BTreeMap<String, VulnerabilityDetails>,
    // PURL to backtrace
    pub purl_to_backtrace: BTreeMap<String, BTreeSet<Vec<String>>>,
    // total number of PURLs
    pub total: usize,
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
