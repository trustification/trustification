use patternfly_yew::prelude::Navigation;
use std::ops::Deref;
use yew::prelude::*;

pub const DEFAULT_PAGE_SIZE: usize = 10;

#[derive(Clone, PartialEq, Properties, Eq)]
pub struct UsePaginationStateArgs {
    pub initial_items_per_page: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PaginationState {
    pub page: usize,
    pub per_page: usize,
}

impl Default for PaginationState {
    fn default() -> Self {
        Self {
            page: 1,
            per_page: DEFAULT_PAGE_SIZE,
        }
    }
}

#[derive(PartialEq, Clone)]
pub struct UsePaginationState {
    pub state: UseStateHandle<PaginationState>,
    pub on_page_change: Callback<(Navigation, usize)>,
    pub on_per_page_change: Callback<usize>,
}

impl Deref for UsePaginationState {
    type Target = PaginationState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

#[hook]
pub fn use_pagination_state<T>(config: T) -> UsePaginationState
where
    T: FnOnce() -> UsePaginationStateArgs,
{
    let state = use_state_eq(|| {
        let args = config();
        PaginationState {
            per_page: args.initial_items_per_page,
            page: 1,
        }
    });

    let on_page_change = {
        let state = state.clone();

        Callback::from(move |nav_and_total: (Navigation, usize)| {
            let state = state.clone();

            let newpage = match nav_and_total.0 {
                Navigation::First => 1,
                Navigation::Last => (nav_and_total.1 + (*state).per_page - 1) / (*state).per_page,
                Navigation::Next => (*state).page + 1,
                Navigation::Previous => (*state).page - 1,
                Navigation::Page(page) => page,
            };
            let newpage = if newpage >= 1 { newpage } else { 1 };
            state.set(PaginationState {
                page: newpage,
                per_page: (*state).per_page,
            });
        })
    };

    let on_per_page_change = {
        let state = state.clone();
        Callback::from(move |per_page: usize| {
            state.set(PaginationState {
                page: (*state).page,
                per_page,
            })
        })
    };

    UsePaginationState {
        state,
        on_page_change,
        on_per_page_change,
    }
}
