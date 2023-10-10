use crate::{
    hooks::{use_generic_search, UseStandardSearch},
    search::*,
};
use patternfly_yew::prelude::UsePagination;
use spog_ui_backend::CveService;
use spog_ui_common::utils::pagination_to_offset;
use spog_ui_utils::config::use_config;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use v11y_model::search::{Cves, SearchDocument};
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(PartialEq, Properties)]
pub struct CveSearchControlsProperties {
    pub search_params: UseStateHandle<SearchMode<DynamicSearchParameters>>,
}

#[function_component(CveSearchControls)]
pub fn cve_search_controls(props: &CveSearchControlsProperties) -> Html {
    let config = use_config();
    let filters = use_memo((), |()| config.cve.filters.clone());

    let search_config = {
        use_memo((), move |()| {
            let search = convert_search(&filters);
            search.apply_defaults(&props.search_params);
            search
        })
    };

    html!(
        <SimpleSearch<DynamicSearchParameters> search={search_config} search_params={props.search_params.clone()} />
    )
}

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
        || config.cve.filters.clone(),
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
