use crate::backend::{SearchOptions, VulnerabilityService};
use crate::hooks::use_backend;
use csaf::Csaf;
use patternfly_yew::{
    next::{Toolbar, ToolbarContent},
    prelude::*,
};
use spog_model::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncHandleDeps};

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

    let offset = use_state_eq(|| 0);
    let limit = use_state_eq(|| 10);

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
            move |(state, offset, limit)| async move {
                service
                    .search(
                        &state,
                        &SearchOptions {
                            offset: Some(offset),
                            limit: Some(limit),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            ((*state).clone(), *offset, *limit),
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
    let onlimit = {
        let limit = limit.clone();
        Callback::from(move |n| {
            limit.set(n);
        })
    };
    let onnavigation = {
        if let Some(total) = total {
            let offset = offset.clone();

            let limit = limit.clone();
            Callback::from(move |nav| {
                let o = match nav {
                    Navigation::First => 0,
                    Navigation::Last => total - *limit,
                    Navigation::Next => *offset + *limit,
                    Navigation::Previous => *offset - *limit,
                    Navigation::Page(n) => *limit * n - 1,
                };
                offset.set(o);
            })
        } else {
            Callback::default()
        }
    };

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
                        <Pagination
                            total_entries={total}
                            selected_choice={*limit}
                            offset={*offset}
                            entries_per_page_choices={vec![10, 25, 50]}
                            {onnavigation}
                            {onlimit}
                        >
                        </Pagination>
                    </ToolbarItem>

                </ToolbarContent>
                // <ToolbarContent> { for filters.into_iter() } </ToolbarContent>
            </Toolbar>

        </>
    )
}
