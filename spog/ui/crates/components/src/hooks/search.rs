use crate::search::{DynamicSearchParameters, SearchMode};
use patternfly_yew::prelude::*;
use spog_model::config::Filters;
use spog_ui_backend::{use_backend, Backend};
use spog_ui_common::utils::search::*;
use std::future::Future;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::{use_async_with_cloned_deps, UseAsyncHandleDeps};
use yew_oauth2::prelude::{use_latest_access_token, LatestAccessToken};

#[derive(Clone)]
pub struct UseStandardSearch {
    pub search_params: UseStateHandle<SearchMode<DynamicSearchParameters>>,
    pub filter_input_state: Rc<InputState>,
    pub onclear: Callback<()>,
    pub onset: Callback<()>,
    pub ontogglesimple: Callback<bool>,
    pub text: UseStateHandle<String>,
}

#[hook]
pub fn use_standard_search<S>(
    search_params: UseStateHandle<SearchMode<DynamicSearchParameters>>,
    context: Rc<Filters>,
) -> UseStandardSearch
where
    S: sikula::prelude::Search,
{
    // the current value in the text input field
    let text = use_state_eq(|| match &*search_params {
        SearchMode::Complex(s) => s.clone(),
        SearchMode::Simple(s) => s.terms().join(" "),
    });

    // parse filter
    let filter_input_state = use_memo(
        |(simple, text)| match simple {
            true => InputState::Default,
            false => match S::parse(text) {
                Ok(_) => InputState::Default,
                Err(err) => {
                    log::info!("Failed to parse: {err}");
                    InputState::Error
                }
            },
        },
        ((*search_params).is_simple(), (*text).clone()),
    );

    // clear search, keep mode
    let onclear = use_callback(
        |_, (text, search_params)| {
            text.set(String::new());
            // trigger empty search
            match **search_params {
                SearchMode::Complex(_) => search_params.set(SearchMode::Complex(String::new())),
                SearchMode::Simple(_) => search_params.set(SearchMode::Simple(Default::default())),
            }
        },
        (text.clone(), search_params.clone()),
    );

    // apply text field to search
    let onset = use_callback(
        |(), (text, search_params)| match (**search_params).clone() {
            SearchMode::Complex(_) => {
                search_params.set(SearchMode::Complex((**text).clone()));
            }
            SearchMode::Simple(mut s) => {
                *s.terms_mut() = text.split(' ').map(|s| s.to_string()).collect();
                search_params.set(SearchMode::Simple(s));
            }
        },
        (text.clone(), search_params.clone()),
    );

    let ontogglesimple = use_callback(
        |state, (text, context, search_params)| match state {
            false => {
                let q = (*search_params).as_str(context).to_string();
                search_params.set(SearchMode::Complex(q.clone()));
                text.set(q);
            }
            true => {
                // TODO: this will reset the query, which we should confirm first
                search_params.set(SearchMode::default());
                text.set(String::new());
            }
        },
        (text.clone(), context.clone(), search_params.clone()),
    );

    UseStandardSearch {
        search_params,
        text,
        filter_input_state,
        onset,
        onclear,
        ontogglesimple,
    }
}

pub struct SearchOperationContext {
    pub backend: Rc<Backend>,
    pub access_token: Option<LatestAccessToken>,
    pub page: usize,
    pub per_page: usize,
    pub search_params: SearchMode<DynamicSearchParameters>,
    pub filters: Rc<Filters>,
}

#[hook]
pub fn use_generic_search<S, R, F, Fut, IF>(
    search_params: UseStateHandle<SearchMode<DynamicSearchParameters>>,
    pagination: UsePagination,
    callback: Callback<UseAsyncHandleDeps<R, String>>,
    init_filter: IF,
    f: F,
) -> UseStandardSearch
where
    S: sikula::prelude::Search,
    R: Clone + PartialEq + 'static,
    IF: FnOnce() -> Filters,
    F: FnOnce(SearchOperationContext) -> Fut + 'static,
    Fut: Future<Output = Result<R, String>> + 'static,
{
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let filters = use_memo(|()| init_filter(), ());

    let search = use_standard_search::<S>(search_params.clone(), filters.clone());

    let search_op = {
        let filters = filters.clone();
        use_async_with_cloned_deps(
            move |(search_params, page, per_page)| async move {
                f(SearchOperationContext {
                    backend: backend.clone(),
                    access_token,
                    page,
                    per_page,
                    search_params,
                    filters,
                })
                .await
            },
            ((*search_params).clone(), pagination.page, pagination.per_page),
        )
    };

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (callback.clone(), search_op.clone()),
    );

    search
}
