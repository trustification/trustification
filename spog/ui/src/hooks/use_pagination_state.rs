use patternfly_yew::Navigation;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties, Eq)]
pub struct UsePaginationStateArgs {
    pub initial_items_per_page: usize,
}

pub struct PaginationState {
    pub page: usize,
    pub per_page: usize,
    pub on_page_change: Callback<(Navigation, usize)>,
    pub on_per_page_change: Callback<usize>,
}

#[hook]
pub fn use_pagination_state<T>(config: T) -> PaginationState
where
    T: FnOnce() -> UsePaginationStateArgs,
{
    let args = config();

    let page = use_state_eq(|| 1);
    let items_per_page = use_state_eq(|| args.initial_items_per_page);

    let on_page_change = {
        let page = page.clone();
        let items_per_page = items_per_page.clone();

        Callback::from(move |nav_and_total: (Navigation, usize)| {
            let page = page.clone();
            let items_per_page = items_per_page.clone();

            let newpage = match nav_and_total.0 {
                Navigation::First => 1,
                Navigation::Last => (nav_and_total.1 + *items_per_page - 1) / *items_per_page,
                Navigation::Next => *page + 1,
                Navigation::Previous => *page - 1,
                Navigation::Page(page) => page,
            };
            page.set(if newpage >= 1 { newpage } else { 1 });
        })
    };

    let on_per_page_change = {
        let items_per_page = items_per_page.clone();
        Callback::from(move |val: usize| {
            items_per_page.set(val);
        })
    };

    PaginationState {
        page: *page,
        per_page: *items_per_page,
        on_page_change: on_page_change,
        on_per_page_change: on_per_page_change,
    }
}
