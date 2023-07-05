use crate::{
    backend::{SearchOptions, VexService},
    components::simple_pagination::SimplePagination,
    hooks::{use_backend::use_backend, use_pagination_state::*},
    utils::pagination_to_offset,
};
use gloo_utils::format::JsValueSerdeExt;
use patternfly_yew::prelude::*;
use sikula::prelude::*;
use spog_model::prelude::*;
use std::borrow::Cow;
use std::collections::HashSet;
use std::rc::Rc;
use vexination_model::prelude::Vulnerabilities;
use wasm_bindgen::JsValue;
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

    let pagination_state = use_pagination_state(|| UsePaginationStateArgs {
        initial_items_per_page: 10,
    });

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |(search_params, page, per_page)| async move {
                service
                    .search_advisories(
                        &search_params.as_str(),
                        &SearchOptions {
                            offset: Some(pagination_to_offset(page, per_page)),
                            limit: Some(per_page),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            (
                (*search_params).clone(),
                pagination_state.page,
                pagination_state.per_page,
            ),
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
            false => match Vulnerabilities::parse(text) {
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

    let hidden = text.is_empty();

    // filter

    let filter_expansion = use_state(|| {
        let mut init = HashSet::new();
        init.insert("Product");
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
                    </Toolbar>

                </GridItem>

                <GridItem cols={[2]}>
                    <Accordion large=true bordered=true>

                        { filter_section("Product", html!(
                            <List r#type={ListType::Plain}>
                                <Check
                                    checked={(*search_params).map(|s|s.is_rhel9)}
                                    onchange={search_set(&search_params, |s, state|s.is_rhel9=state)}
                                    disabled={!simple}
                                >
                                    { "Red Hat Enterprise Linux 9" }
                                </Check>
                            </List>
                        ))}

                    </Accordion>
                </GridItem>

                <GridItem cols={[10]}>
                    { for props.children.iter() }
                </GridItem>

            </Grid>

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
    terms: Vec<String>,

    is_rhel9: bool,
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
                let mut terms = s.terms.clone();

                if s.is_rhel9 {
                    terms.extend([
                        r#"package:"cpe:/a:redhat:enterprise_linux:9::appstream""#.to_string(),
                        r#"package:"cpe:/a:redhat:enterprise_linux:9::crb""#.to_string(),
                    ]);
                }

                terms.join(" ").into()
            }
        }
    }
}

impl Default for SearchMode {
    fn default() -> Self {
        Self::Simple(Default::default())
    }
}
