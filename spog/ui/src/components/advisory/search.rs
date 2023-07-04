use crate::{
    backend::{SearchOptions, VexService},
    components::simple_pagination::SimplePagination,
    hooks::{use_backend::use_backend, use_pagination_state::*},
    utils::pagination_to_offset,
};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncHandleDeps};

#[derive(PartialEq, Properties)]
pub struct AdvisorySearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>>,

    pub query: Option<String>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,

    #[prop_or_default]
    pub children: Children,
}

#[function_component(AdvisorySearch)]
pub fn advisory_search(props: &AdvisorySearchProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(|backend| VexService::new(backend.clone()), backend.clone());

    // the active query
    let state = use_state_eq(|| {
        // initialize with the state from history, or with a reasonable default
        gloo_utils::history()
            .state()
            .ok()
            .and_then(|state| state.as_string())
            .unwrap_or_else(|| props.query.clone().unwrap_or(String::default()))
    });

    let pagination_state = use_pagination_state(|| UsePaginationStateArgs {
        initial_items_per_page: 10,
    });

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |(state, page, per_page)| async move {
                service
                    .search_advisories(
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

    let hidden = text.is_empty();

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
                                            placeholder="Search"
                                            value={(*text).clone()}
                                            oninput={ Callback::from(move |data| text.set(data)) }
                                        />
                                        if !hidden {
                                            <TextInputGroupUtilities>
                                                <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclear} />
                                            </TextInputGroupUtilities>
                                        }
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
                            on_page_change={&pagination_state.on_page_change}
                            on_per_page_change={&pagination_state.on_per_page_change}
                        />
                    </ToolbarItem>

                </ToolbarContent>
                // <ToolbarContent> { for filters.into_iter() } </ToolbarContent>
            </Toolbar>

            { for props.children.iter() }

            <SimplePagination
                position={PaginationPosition::Bottom}
                total_items={total}
                page={pagination_state.page}
                per_page={pagination_state.per_page}
                on_page_change={pagination_state.on_page_change}
                on_per_page_change={pagination_state.on_per_page_change}
            />

        </>
    )
}
