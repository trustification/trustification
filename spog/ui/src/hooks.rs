use spog_model::prelude::*;
use spog_ui_backend::{use_backend, SearchParameters, VexService};
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::*;
use yew_oauth2::hook::use_latest_access_token;

/// A hook to retrieve the advisories related to a CVE
#[hook]
pub fn use_related_advisories(id: String) -> UseAsyncHandleDeps<Rc<Vec<AdvisorySummary>>, String> {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    use_async_with_cloned_deps(
        |id| async move {
            let service = VexService::new(backend.clone(), access_token.clone());
            service
                .search_advisories(&format!(r#"cve:{id}"#), &SearchParameters::default())
                .await
                .map(|r| {
                    let mut related = r.result;
                    related.sort_unstable_by(|a, b| a.id.cmp(&b.id));
                    Rc::new(related)
                })
                .map_err(|err| err.to_string())
        },
        id,
    )
}
