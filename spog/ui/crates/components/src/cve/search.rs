use crate::hooks::{use_generic_search, UseStandardSearch};
use crate::search::{DynamicSearchParameters, SearchMode};
use patternfly_yew::prelude::UsePagination;
use spog_ui_backend::CveService;
use spog_ui_common::utils::pagination_to_offset;
use spog_ui_utils::config::use_config;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use v11y_model::search::{Cves, SearchDocument};
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[hook]
pub fn use_cve_search(
    search_params: UseStateHandle<SearchMode<DynamicSearchParameters>>,
    pagination: UsePagination,
    callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<SearchDocument>>>, String>>,
) -> UseStandardSearch {
    let config = use_config();
    use_generic_search::<Cves, _, _, _, _>(
        search_params,
        pagination,
        callback,
        || config.vexination.filters.clone(),
        |context| async move {
            let service = CveService::new(context.backend.clone(), context.access_token);
            service
                .search(
                    &context.search_params.as_str(&context.filters),
                    &spog_ui_backend::SearchParameters {
                        offset: Some(pagination_to_offset(context.page, context.per_page)),
                        limit: Some(context.per_page),
                        ..Default::default()
                    },
                )
                .await
                .map(|result| result.map(Rc::new))
                .map_err(|err| err.to_string())
        },
    )
}
