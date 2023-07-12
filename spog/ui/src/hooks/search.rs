use crate::components::search::SearchMode;
use crate::hooks::use_pagination_state::{
    use_pagination_state, PaginationState, UsePaginationState, UsePaginationStateArgs, DEFAULT_PAGE_SIZE,
};
use crate::utils::search::*;
use gloo_utils::format::JsValueSerdeExt;
use patternfly_yew::prelude::InputState;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use wasm_bindgen::JsValue;
use yew::prelude::*;

#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SearchViewState<T> {
    pub search: T,
    pub pagination: PaginationState,
}

impl<T> Deref for SearchViewState<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.search
    }
}

impl<T> DerefMut for SearchViewState<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.search
    }
}

#[hook]
pub fn use_search_view_state<T, F>(props_query: Option<String>, f: F) -> (UseStateHandle<T>, UsePaginationState)
where
    T: for<'de> serde::Deserialize<'de> + serde::Serialize + Clone + Default + Debug + PartialEq + 'static,
    F: FnOnce(String) -> T,
{
    // the active query
    let state = use_state_eq(move || {
        // initialize with the state from history, properties, or with a reasonable default
        gloo_utils::history()
            .state()
            .ok()
            .and_then(|state| {
                let deser = state.into_serde::<SearchViewState<T>>();
                log::debug!("Deserialized: {deser:?}");
                deser.ok()
            })
            .or_else(move || {
                props_query.and_then(|s| {
                    log::debug!("Initial: {s}");
                    match s.is_empty() {
                        true => None,
                        false => Some(SearchViewState {
                            search: f(s),
                            ..Default::default()
                        }),
                    }
                })
            })
            .unwrap_or_default()
    });

    let search_params = use_state_eq(T::default);
    let pagination_state = use_pagination_state(|| UsePaginationStateArgs {
        initial_items_per_page: DEFAULT_PAGE_SIZE,
    });

    {
        let search_params = search_params.clone();
        let pagination_state = pagination_state.clone();
        use_effect_with_deps(
            move |state| {
                search_params.set(state.search.clone());
                pagination_state.state.set(state.pagination.clone());
            },
            (*state).clone(),
        );
    }

    use_effect_with_deps(
        |(search_params, pagination)| {
            // store changes to the state in the current history
            if let Ok(data) = JsValue::from_serde(&SearchViewState {
                search: search_params,
                pagination: pagination.clone(),
            }) {
                let _ = gloo_utils::history().replace_state(&data, "");
            }
        },
        ((*search_params).clone(), (*pagination_state.state).clone()),
    );

    (search_params, pagination_state)
}

pub struct UseStandardSearch<T> {
    pub search_params: UseStateHandle<SearchMode<T>>,
    pub pagination_state: UsePaginationState,
    pub filter_input_state: Rc<InputState>,
    pub onclear: Callback<MouseEvent>,
    pub onset: Callback<()>,
    pub ontogglesimple: Callback<bool>,
    pub text: UseStateHandle<String>,
}

#[hook]
pub fn use_standard_search<T, S>(props_query: Option<String>) -> UseStandardSearch<T>
where
    T: for<'de> serde::Deserialize<'de>
        + serde::Serialize
        + Clone
        + Default
        + Debug
        + PartialEq
        + ToFilterExpression
        + SimpleProperties
        + 'static,
    S: sikula::prelude::Search,
{
    let (search_params, pagination_state) = use_search_view_state::<SearchMode<T>, _>(props_query, SearchMode::Complex);

    // the current value in the text input field
    let text = use_state_eq(|| match &*search_params {
        SearchMode::Complex(s) => s.to_string(),
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
    let onclear = {
        let text = text.clone();
        let search_params = search_params.clone();
        Callback::from(move |_| {
            text.set(String::new());
            // trigger empty search
            match *search_params {
                SearchMode::Complex(_) => search_params.set(SearchMode::Complex(String::new())),
                SearchMode::Simple(_) => search_params.set(SearchMode::Simple(Default::default())),
            }
        })
    };

    // apply text field to search
    let onset = {
        let search_params = search_params.clone();
        let text = text.clone();
        Callback::from(move |()| match (*search_params).clone() {
            SearchMode::Complex(_) => {
                search_params.set(SearchMode::Complex((*text).clone()));
            }
            SearchMode::Simple(mut s) => {
                let text = &*text;
                *s.terms_mut() = text.split(" ").map(|s| s.to_string()).collect();
                search_params.set(SearchMode::Simple(s));
            }
        })
    };

    let ontogglesimple = {
        let search_params = search_params.clone();
        let text = text.clone();

        Callback::from(move |state| match state {
            false => {
                let q = (*search_params).as_str().to_string();
                search_params.set(SearchMode::Complex(q.clone()));
                text.set(q);
            }
            true => {
                search_params.set(SearchMode::default());
                text.set(String::new());
            }
        })
    };

    UseStandardSearch {
        search_params,
        pagination_state,
        text,
        filter_input_state,
        onset,
        onclear,
        ontogglesimple,
    }
}
