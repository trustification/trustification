use super::SEARCH_CHUNK_SIZE;
use crate::error::Error;
use crate::server::AppState;
use bytes::BytesMut;
use csaf::Csaf;
use futures::{stream, StreamExt, TryStreamExt};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use tracing::instrument;
use trustification_api::search::SearchOptions;
use trustification_auth::client::TokenProvider;

/// take a set of CVE id and fetch their related CSAF documents
#[instrument(skip_all, fields(num_ids), err)]
pub async fn collect_vex<'a>(
    state: &AppState,
    token: &dyn TokenProvider,
    ids: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<HashMap<String, Vec<Rc<Csaf>>>, Error> {
    let ids = ids.into_iter();
    let (_, num_ids) = ids.size_hint();
    tracing::Span::current().record("num_ids", num_ids);

    let ids = ids.filter(|id| !id.as_ref().is_empty());

    // a stream of chunked queries
    let cves = stream::iter(ids)
        // request in chunks of 10
        .ready_chunks(SEARCH_CHUNK_SIZE)
        .map(Ok)
        .and_then(|ids| async move {
            let q = ids
                .iter()
                .map(|id| format!(r#"cve:"{}""#, id.as_ref()))
                .collect::<Vec<_>>()
                .join(" OR ");

            // lookup documents (limit to 1.000, which should be reasonable)
            let result = state.search_vex(&q, 0, 1000, SearchOptions::default(), token).await?;

            Ok::<HashSet<_>, Error>(result.result.into_iter().map(|hit| hit.document.advisory_id).collect())
        });

    // flatten the result stream
    let cves: HashSet<String> = cves.try_collect::<Vec<_>>().await?.into_iter().flatten().collect();

    // now fetch the documents and sort them in the result map
    let result: HashMap<String, Vec<_>> = stream::iter(cves)
        .map(|id| async move {
            let doc: BytesMut = state.get_vex(&id, token).await?.try_collect().await?;

            let mut result = Vec::new();

            if let Ok(doc) = serde_json::from_slice::<Csaf>(&doc) {
                let doc = Rc::new(doc);
                if let Some(v) = &doc.vulnerabilities {
                    for v in v {
                        if let Some(cve) = v.cve.clone() {
                            result.push((cve, doc.clone()))
                        }
                    }
                }
            }

            Ok::<_, Error>(result)
        })
        // fetch parallel
        .buffer_unordered(PARALLEL_FETCH_VEX)
        // fold them into a single result
        .try_fold(HashMap::<String, Vec<Rc<Csaf>>>::new(), |mut acc, x| async move {
            for (id, docs) in x {
                acc.entry(id).or_default().push(docs);
            }
            Ok(acc)
        })
        .await?;

    Ok(result)
}
