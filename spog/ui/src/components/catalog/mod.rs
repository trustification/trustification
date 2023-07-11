use crate::{
    backend::{PackageService, SearchOptions},
    components::{search::*, severity::Severity, simple_pagination::SimplePagination},
    hooks::{use_backend::use_backend, use_pagination_state::*},
    utils::pagination_to_offset,
};
use bombastic_model::prelude::Packages;
use gloo_utils::format::JsValueSerdeExt;
use lazy_static::lazy_static;
use patternfly_yew::prelude::*;
use sikula::prelude::Search as _;
use spog_model::prelude::*;
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

    // the active query
    let search_params = use_state_eq(|| {
        // initialize with the state from history, properties, or with a reasonable default
        gloo_utils::history()
            .state()
            .ok()
            .and_then(|state| {
                let deser = state.into_serde::<SearchMode<SearchParameters>>();
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
                    .search_packages(
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

    // filter

    let hidden = text.is_empty();
    let filter_expansion = use_state(|| SEARCH.category_labels::<HashSet<_>>());

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
                    { simple_search(&SEARCH, search_params.clone(), filter_expansion.clone()) }
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

lazy_static! {
    static ref SEARCH: Search<SearchParameters> = Search {
        categories: vec![
            SearchCategory {
                title: "Supplier",
                options: vec![SearchOption::<SearchParameters>::new_str(
                    "Red Hat",
                    |options| options.supplier_redhat,
                    |options, value| options.supplier_redhat = value
                ),]
            },
            SearchCategory {
                title: "Type",
                options: vec![SearchOption::<SearchParameters>::new_str(
                    "Container",
                    |options| options.is_container,
                    |options, value| options.is_container = value
                ),]
            }
        ]
    };
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct SearchParameters {
    terms: Vec<String>,

    supplier_redhat: bool,
    is_container: bool,
}

impl ToFilterExpression for SearchParameters {
    fn to_filter_expression(&self) -> String {
        let mut terms = self.terms.clone();

        if self.is_container {
            terms.push("type:oci".to_string());
        }

        if self.supplier_redhat {
            terms.push(r#"supplier:"Organization: Red Hat""#.to_string());
        }

        terms.join(" ")
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
