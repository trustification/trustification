use crate::backend::{PackageService, SearchOptions};
use crate::hooks::use_backend::use_backend;
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::{collections::HashSet, rc::Rc};
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(PartialEq, Properties)]
pub struct CatalogSearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>>,

    pub query: Option<String>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,

    #[prop_or_default]
    pub children: Children,
}

#[function_component(CatalogSearch)]
pub fn catalog_search(props: &CatalogSearchProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(|backend| PackageService::new(backend.clone()), backend.clone());

    let offset = use_state_eq(|| 0);
    let limit = use_state_eq(|| 10);

    // the active query
    let state = use_state_eq(|| {
        // initialize with the state from history, or with a reasonable default
        props.query.clone().unwrap_or_else(|| {
            gloo_utils::history()
                .state()
                .ok()
                .and_then(|state| state.as_string())
                .unwrap_or_else(String::default)
        })
    });

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |(state, offset, limit)| async move {
                service
                    .search_packages(
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

    let text_state = use_memo(|text| {}, (*text).clone());

    let onclear = {
        let text = text.clone();
        let state = state.clone();
        Callback::from(move |_| {
            text.set(String::new());
            // trigger empty search
            state.set(String::new());
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

    let hidden = text.is_empty();

    let filter_expansion = use_state(|| {
        let mut init = HashSet::new();
        init.insert("Supplier");
        init.insert("Architecture");
        init.insert("Type");
        init
    });

    let filter_section = |title: &'static str, children: Html| {
        let expanded = filter_expansion.contains(title);

        let onclick = {
            let filter_expansion = filter_expansion.clone();
            Callback::from(move |()| {
                let mut selection = (*filter_expansion).clone();
                if selection.contains(title) {
                    selection.remove(title);
                } else {
                    selection.insert(title);
                }
                filter_expansion.set(selection);
            })
        };

        html_nested!(
            <AccordionItem title={title.to_string()} {expanded} {onclick}>
                { children }
            </AccordionItem>
        )
    };

    // render
    html!(
        <>

            <Grid>
                <GridItem cols={[2]}>
                    <div style="height: 100%; display: flex; flex-direction: row; align-items: center;">
                        <Title level={Level::H2}>{ "Categories" }</Title>
                    </div>
                </GridItem>
                <GridItem cols={[10]}>

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
                                            </TextInputGroup>
                                            <InputGroupItem>
                                                <Button icon={Icon::ArrowRight} variant={ButtonVariant::Control} onclick={onset.reform(|_|())} />
                                            </InputGroupItem>
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
                    </Toolbar>

                </GridItem>

                <GridItem cols={[2]}>
                    <Accordion large=true bordered=true>
                        { filter_section("Supplier", html!(
                            <List r#type={ListType::Plain}>
                                <Check>{ "Red Hat" }</Check>
                            </List>
                        ))}
                        { filter_section("Type", html!(
                            <List r#type={ListType::Plain}>
                                <Check>{ "Container" }</Check>
                            </List>
                        ))}
                        { filter_section("Architecture", html!(
                            <List r#type={ListType::Plain}>
                                <Check>{ "amd64" }</Check>
                                <Check>{ "aarch64" }</Check>
                                <Check>{ "s390" }</Check>
                            </List>
                        ))}
                    </Accordion>
                </GridItem>

                <GridItem cols={[10]}>

                    { for props.children.iter() }

                </GridItem>

            </Grid>

        </>
    )
}
