use crate::backend::{SearchOptions, VulnerabilityService};
use crate::hooks::use_backend::use_backend;
use csaf::Csaf;
use patternfly_yew::{
    next::{Toolbar, ToolbarContent},
    prelude::*,
};
use spog_model::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncHandleDeps};

use crate::utils::pagination_to_offset;

use crate::components::simple_pagination::SimplePagination;
use crate::hooks::use_pagination_state::{use_pagination_state, UsePaginationStateArgs};

#[derive(PartialEq, Properties)]
pub struct VexinationSearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<Csaf>>>, String>>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,
}

#[function_component(VexinationSearch)]
pub fn vexination_search(props: &VexinationSearchProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(
        |backend| VulnerabilityService::new((**backend).clone()),
        backend.clone(),
    );

    let pagination_state = use_pagination_state(|| UsePaginationStateArgs {
        initial_items_per_page: 10,
    });

    // the active query
    let state = use_state_eq(|| {
        // initialize with the state from history, or with a reasonable default
        gloo_utils::history()
            .state()
            .ok()
            .and_then(|state| state.as_string())
            .unwrap_or_else(String::default)
    });

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |(state, page, per_page)| async move {
                service
                    .search(
                        &state,
                        &SearchOptions {
                            offset: Some(pagination_to_offset(page, per_page)),
                            limit: Some(per_page),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            ((*state).clone(), pagination_state.page, pagination_state.per_page),
        )
    };

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (props.callback.clone(), search.clone()),
    );

    // the current value in the text input field
    let text = use_state_eq(|| (*state).clone());

    let onclear = {
        let text = text.clone();
        Callback::from(move |_| {
            text.set(String::new());
        })
    };
    let onset = {
        let state = state.clone();
        let text = text.clone();
        Callback::from(move |()| {
            state.set((*text).clone());
        })
    };

    use_effect_with_deps(
        |query| {
            // store changes to the state in the current history
            let _ = gloo_utils::history().replace_state(&query.into(), "");
        },
        (*state).clone(),
    );

    // pagination

    let total = search.data().and_then(|d| d.total);

    // render

    html!(
        <>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarGroup>
                        <ToolbarItem r#type={ToolbarItemType::SearchFilter} width={["600px".to_string()]}>
                            <Form onsubmit={onset.reform(|_|())}>
                                // needed to trigger submit when pressing enter in the search field
                                <input type="submit" hidden=true formmethod="dialog" />
                                <InputGroup>
                                    <TextInputGroup>
                                        <TextInputGroupMain
                                            icon={Icon::Search}
                                            placeholder="Filter"
                                            value={(*text).clone()}
                                            oninput={ Callback::from(move |data| text.set(data)) }
                                        />
                                        <TextInputGroupUtilities>
                                            <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclear} />
                                        </TextInputGroupUtilities>
                                        <Button icon={Icon::ArrowRight} variant={ButtonVariant::Control} onclick={onset.reform(|_|())} />
                                    </TextInputGroup>
                                </InputGroup>
                            </Form>
                        </ToolbarItem>
                    </ToolbarGroup>

                    { for props.toolbar_items.iter() }

                    <ToolbarItem r#type={ToolbarItemType::Pagination}>
                        <SimplePagination
                            total_items={total}
                            page={pagination_state.page}
                            per_page={pagination_state.per_page}
                            on_page_change={pagination_state.on_page_change}
                            on_per_page_change={pagination_state.on_per_page_change}
                        />
                    </ToolbarItem>

                </ToolbarContent>
                // <ToolbarContent> { for filters.into_iter() } </ToolbarContent>
            </Toolbar>

        </>
    )
}
