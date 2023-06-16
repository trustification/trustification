use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct SimplePaginationProps {
    pub total_items: Option<usize>,
    pub page: usize,
    pub per_page: usize,
    pub on_page_change: Callback<(Navigation, usize)>,
    pub on_per_page_change: Callback<usize>,
}

#[function_component(SimplePagination)]
pub fn simple_pagination(props: &SimplePaginationProps) -> Html {
    let onnavigation = {
        if let Some(total) = props.total_items {
            let on_page_change = props.on_page_change.clone();
            Callback::from(move |nav: Navigation| {
                on_page_change.emit((nav, total));
            })
        } else {
            Callback::default()
        }
    };

    html!(
        <Pagination
            total_entries={props.total_items}
            offset={(props.page - 1) * props.per_page}
            selected_choice={props.per_page}
            entries_per_page_choices={vec![10, 25, 50]}
            onnavigation={onnavigation}
            onlimit={&props.on_per_page_change}
        />
    )
}
