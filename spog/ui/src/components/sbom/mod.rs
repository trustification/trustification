use crate::{
    backend::{PackageService, SearchOptions},
    components::search::*,
    hooks::{use_backend::use_backend, use_config, use_standard_search, UseStandardSearch},
    utils::{pagination_to_offset, search::*},
};
use bombastic_model::prelude::Packages;
use lazy_static::lazy_static;
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::collections::HashSet;
use std::rc::Rc;
use std::sync::Arc;
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

    let config = use_config();

    let service = use_memo(|backend| PackageService::new(backend.clone()), backend);

    let total = use_state_eq(|| None);

    let filters = use_memo(|()| config.bombastic.filters.clone(), ());
    let search_config = use_memo(|()| convert_search(&filters), ());

    let UseStandardSearch {
        search_params,
        pagination,
        filter_input_state,
        onclear,
        onset,
        ontogglesimple,
        text,
    } = use_standard_search::<DynamicSearchParameters, Packages>(props.query.clone(), *total, filters.clone());

    let search = {
        let filters = filters.clone();
        use_async_with_cloned_deps(
            move |(search_params, page, per_page)| async move {
                service
                    .search_packages(
                        &search_params.as_str(&filters),
                        &SearchOptions {
                            offset: Some(pagination_to_offset(page, per_page)),
                            limit: Some(per_page),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            ((*search_params).clone(), pagination.page, pagination.per_page),
        )
    };

    total.set(search.data().and_then(|d| d.total));

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (props.callback.clone(), search.clone()),
    );

    // pagination

    let total = search.data().and_then(|d| d.total);

    // filter

    let hidden = text.is_empty();

    // switch

    let simple = search_params.is_simple();
    let simple_search = use_simple_search(search_config, search_params);

    // render
    html!(
        <>

            <Grid>
                <GridItem cols={[2]}>
                    <SimpleModeSwitch {simple} ontoggle={ontogglesimple} />
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
                                    pagination={pagination.clone()}
                                    total={total}
                                />
                            </ToolbarItem>

                        </ToolbarContent>
                    </Toolbar>

                </GridItem>

                <GridItem cols={[2]}>
                    { (*simple_search).clone() }
                </GridItem>

                <GridItem cols={[10]}>
                    { for props.children.iter() }
                </GridItem>

            </Grid>

            <SimplePagination
                {pagination}
                total={total}
                position={PaginationPosition::Bottom}
            />

        </>
    )
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DynamicSearchParameters {
    terms: Vec<String>,
    state: HashSet<(Arc<String>, Arc<String>)>,
}

impl DynamicSearchParameters {
    pub fn get(&self, cat: Arc<String>, id: Arc<String>) -> bool {
        self.state.contains(&(cat, id))
    }

    pub fn set(&mut self, cat: Arc<String>, id: Arc<String>, value: bool) {
        if value {
            self.state.insert((cat, id));
        } else {
            self.state.remove(&(cat, id));
        }
    }
}

impl SimpleProperties for DynamicSearchParameters {
    fn terms(&self) -> &[String] {
        &self.terms
    }

    fn terms_mut(&mut self) -> &mut Vec<String> {
        &mut self.terms
    }
}

impl ToFilterExpression for DynamicSearchParameters {
    type Context = Filters;

    fn to_filter_expression(&self, context: &Self::Context) -> String {
        let mut terms = escape_terms(self.terms.clone()).collect::<Vec<_>>();

        for cat in &context.categories {
            for opt in &cat.options {
                if self.get(Arc::new(cat.label.clone()), Arc::new(opt.id.clone())) {
                    terms.extend(or_group(opt.terms.clone()));
                }
            }
        }

        terms.join(" ")
    }
}

fn convert_search(filters: &Filters) -> Search<DynamicSearchParameters> {
    let categories = filters
        .categories
        .iter()
        .map(|cat| {
            let cat_id = Arc::new(cat.label.clone());
            SearchCategory {
                title: cat.label.clone(),
                options: cat
                    .options
                    .iter()
                    .map(|opt| {
                        let label = format!("<div>{}</div>", opt.label);
                        let id = Arc::new(opt.id.clone());
                        SearchOption {
                            label: Arc::new(move || Html::from_html_unchecked(AttrValue::from(label.clone()))),
                            getter: {
                                let cat_id = cat_id.clone();
                                let id = id.clone();
                                Arc::new(move |state: &DynamicSearchParameters| state.get(cat_id.clone(), id.clone()))
                            },
                            setter: {
                                let cat_id = cat_id.clone();
                                let id = id.clone();
                                Arc::new(move |state: &mut DynamicSearchParameters, value| {
                                    state.set(cat_id.clone(), id.clone(), value)
                                })
                            },
                        }
                    })
                    .collect(),
            }
        })
        .collect();

    Search { categories }
}

lazy_static! {
    static ref SEARCH: Search<SearchParameters> = Search {
        categories: vec![
            SearchCategory {
                title: "Product".to_string(),
                options: vec![
                    SearchOption::<SearchParameters>::new_str(
                        "Red Hat Enterprise Linux 7",
                        |options| options.is_rhel7,
                        |options, value| options.is_rhel7 = value
                    ),
                    SearchOption::<SearchParameters>::new_str(
                        "Red Hat Enterprise Linux 8",
                        |options| options.is_rhel8,
                        |options, value| options.is_rhel8 = value
                    ),
                    SearchOption::<SearchParameters>::new_str(
                        "Red Hat Enterprise Linux 9",
                        |options| options.is_rhel9,
                        |options, value| options.is_rhel9 = value
                    )
                ]
            },
            SearchCategory {
                title: "Supplier".to_string(),
                options: vec![SearchOption::<SearchParameters>::new_str(
                    "Red Hat",
                    |options| options.supplier_redhat,
                    |options, value| options.supplier_redhat = value
                ),]
            },
            SearchCategory {
                title: "Type".to_string(),
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

    is_rhel7: bool,
    is_rhel8: bool,
    is_rhel9: bool,

    supplier_redhat: bool,
    is_container: bool,
}

impl SimpleProperties for SearchParameters {
    fn terms(&self) -> &[String] {
        &self.terms
    }

    fn terms_mut(&mut self) -> &mut Vec<String> {
        &mut self.terms
    }
}

impl ToFilterExpression for SearchParameters {
    type Context = ();

    fn to_filter_expression(&self, _: &Self::Context) -> String {
        let mut terms = escape_terms(self.terms.clone()).collect::<Vec<_>>();

        {
            let mut products = vec![];

            if self.is_rhel7 {
                products.push(r#""pkg:oci/redhat/ubi7""#);
            }

            if self.is_rhel8 {
                products.push(r#""pkg:oci/redhat/ubi8""#);
            }

            if self.is_rhel9 {
                products.push(r#""pkg:oci/redhat/ubi9""#);
            }

            terms.extend(or_group(products));
        }

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
