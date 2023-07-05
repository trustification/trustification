use crate::backend::{PackageService, SearchOptions};
use crate::components::search::SearchHelpPopover;
use crate::hooks::use_backend::use_backend;
use bombastic_model::prelude::Packages;
use gloo_utils::format::JsValueSerdeExt;
use patternfly_yew::prelude::*;
use sikula::prelude::*;
use spog_model::prelude::*;
use std::borrow::Cow;
use std::{collections::HashSet, rc::Rc};
use wasm_bindgen::JsValue;
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
    let search_params = use_state_eq(|| {
        // initialize with the state from history, properties, or with a reasonable default
        gloo_utils::history()
            .state()
            .ok()
            .and_then(|state| {
                let deser = state.into_serde::<SearchMode>();
                log::debug!("Deserialized: {deser:?}");
                deser.ok()
            })
            .or_else(|| {
                props.query.clone().map(|s| {
                    log::debug!("Initial: {s}");
                    match s.is_empty() {
                        true => SearchMode::default(),
                        false => SearchMode::Complex(s),
                    }
                })
            })
            .unwrap_or_else(SearchMode::default)
    });

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |(search_params, offset, limit)| async move {
                service
                    .search_packages(
                        &search_params.as_str(),
                        &SearchOptions {
                            offset: Some(offset),
                            limit: Some(limit),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            ((*search_params).clone(), *offset, *limit),
        )
    };

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (props.callback.clone(), search.clone()),
    );

    // the current value in the text input field
    let text = use_state_eq(|| match &*search_params {
        SearchMode::Complex(s) => s.to_string(),
        SearchMode::Simple(s) => s.terms.join(" "),
    });

    // parse filter
    let filter_input_state = use_memo(
        |(simple, text)| match simple {
            true => InputState::Default,
            false => match Packages::parse(text) {
                Ok(_) => InputState::Default,
                Err(_) => InputState::Error,
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
        Callback::from(move |()| {
            let s = (*search_params).clone();
            match s {
                SearchMode::Complex(_) => {
                    search_params.set(SearchMode::Complex((*text).clone()));
                }
                SearchMode::Simple(mut s) => {
                    let text = &*text;
                    s.terms = text.split(" ").map(|s| s.to_string()).collect();
                    search_params.set(SearchMode::Simple(s));
                }
            }
        })
    };

    use_effect_with_deps(
        |search_params| {
            // store changes to the state in the current history
            if let Ok(data) = JsValue::from_serde(search_params) {
                let _ = gloo_utils::history().replace_state(&data, "");
            }
        },
        (*search_params).clone(),
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

    // switch

    let simple = search_params.is_simple();

    // toggle search mode: simple <-> complex
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

    // render
    html!(
        <>

            <Grid>
                <GridItem cols={[2]}>
                    <div style="height: 100%; display: flex; flex-direction: row; align-items: center;">
                        <Title level={Level::H2}>{ "Categories " } <Switch checked={simple} label="Simple" label_off="Complex" onchange={ontogglesimple}/> </Title>
                    </div>
                </GridItem>
                <GridItem cols={[10]}>

                    <Toolbar>
                        <ToolbarContent>
                            <ToolbarGroup variant={GroupVariant::Filter}>
                                <ToolbarItem r#type={ToolbarItemType::SearchFilter} width={["600px".to_string()]}>
                                    <Form onsubmit={onset.reform(|_|())}>
                                        // needed to trigger submit when pressing enter in the search field
                                        <input type="submit" hidden=true formmethod="dialog" />
                                        <InputGroup>
                                            <TextInputGroup>
                                                <TextInput
                                                    icon={Icon::Search}
                                                    placeholder="Search"
                                                    value={(*text).clone()}
                                                    state={*filter_input_state}
                                                    oninput={ Callback::from(move |data| text.set(data)) }
                                                />

                                                if !hidden {
                                                    <TextInputGroupUtilities>
                                                        <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclear} />
                                                    </TextInputGroupUtilities>
                                                }
                                            </TextInputGroup>
                                            <InputGroupItem>
                                                <Button
                                                    disabled={*filter_input_state == InputState::Error}
                                                    icon={Icon::ArrowRight}
                                                    variant={ButtonVariant::Control}
                                                    onclick={onset.reform(|_|())}
                                                />
                                            </InputGroupItem>
                                        </InputGroup>
                                    </Form>
                                </ToolbarItem>

                                <ToolbarItem additional_class={classes!("pf-m-align-self-center")}>
                                    <CatalogSearchHelpPopover/>
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
                                />
                            </ToolbarItem>

                        </ToolbarContent>
                    </Toolbar>

                </GridItem>

                <GridItem cols={[2]}>
                    <Accordion large=true bordered=true>

                        { filter_section("Supplier", html!(
                            <List r#type={ListType::Plain}>
                                <Check
                                    checked={(*search_params).map(|s|s.supplier_redhat)}
                                    onchange={search_set(&search_params, |s, state|s.supplier_redhat=state)}
                                    disabled={!simple}
                                >
                                    { "Red Hat" }
                                </Check>
                            </List>
                        ))}

                        { filter_section("Type", html!(
                            <List r#type={ListType::Plain}>
                                <Check
                                    checked={(*search_params).map(|s|s.is_container)}
                                    onchange={search_set(&search_params, |s, state|s.is_container=state)}
                                    disabled={!simple}
                                >
                                    { "Container" }
                                </Check>
                            </List>
                        ))}

                        { filter_section("Architecture", html!(
                            <List r#type={ListType::Plain}>
                                <Check disabled=true>{ "amd64" }</Check>
                                <Check disabled=true>{ "aarch64" }</Check>
                                <Check disabled=true>{ "s390" }</Check>
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

fn search_set<F>(search: &UseStateHandle<SearchMode>, f: F) -> Callback<bool>
where
    F: Fn(&mut SearchParameters, bool) + 'static,
{
    let search = search.clone();
    Callback::from(move |state| {
        if let SearchMode::Simple(simple) = &*search {
            let mut simple = simple.clone();
            f(&mut simple, state);
            search.set(SearchMode::Simple(simple));
        }
    })
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SearchParameters {
    supplier_redhat: bool,
    is_container: bool,
    terms: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
enum SearchMode {
    Complex(String),
    Simple(SearchParameters),
}

impl SearchMode {
    pub fn is_simple(&self) -> bool {
        matches!(self, Self::Simple(_))
    }

    pub fn map<F>(&self, f: F) -> bool
    where
        F: FnOnce(&SearchParameters) -> bool,
    {
        match self {
            Self::Simple(s) => f(s),
            Self::Complex(_) => false,
        }
    }

    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            Self::Complex(s) => s.into(),
            Self::Simple(s) => {
                let mut q = s.terms.join(" ");

                if s.supplier_redhat {
                    if !q.is_empty() {
                        q.push(' ');
                    }
                    q.push_str(r#"supplier:"Organization: Red Hat""#);
                }

                if s.is_container {
                    if !q.is_empty() {
                        q.push(' ');
                    }
                    q.push_str("type:oci");
                }

                q.into()
            }
        }
    }
}

impl Default for SearchMode {
    fn default() -> Self {
        Self::Simple(Default::default())
    }
}

#[function_component(CatalogSearchHelpPopover)]
pub fn help() -> Html {
    html!(
        <SearchHelpPopover>
            <Content>
                <p></p>
                <p> {"The following qualifiers can be used:"} </p>
            </Content>
            <DescriptionList>
                <DescriptionGroup term="type">{ Html::from_html_unchecked(r#"
                    <p>The type of package (e.g. <code>oci</code>).</p>
                "#.into()) }</DescriptionGroup>
                <DescriptionGroup term="supplier">{ "The supplier of the package." }</DescriptionGroup>
            </DescriptionList>
        </SearchHelpPopover>
    )
}
