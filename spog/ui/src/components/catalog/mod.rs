use crate::{
    backend::{PackageService, SearchOptions},
    components::{search::*, simple_pagination::SimplePagination},
    hooks::{use_backend::use_backend, use_standard_search, UseStandardSearch},
    utils::{pagination_to_offset, search::*},
};
use bombastic_model::prelude::Packages;
use lazy_static::lazy_static;
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

    let service = use_memo(|backend| PackageService::new(backend.clone()), backend);

    let UseStandardSearch {
        search_params,
        pagination_state,
        filter_input_state,
        onclear,
        onset,
        ontogglesimple,
        text,
    } = use_standard_search::<SearchParameters, Packages>(props.query.clone());

    let search = {
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

    // pagination

    let total = search.data().and_then(|d| d.total);

    // filter

    let hidden = text.is_empty();
    let filter_expansion = use_state(|| SEARCH.category_labels::<HashSet<_>>());

    // switch

    let simple = search_params.is_simple();

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
                    { simple_search(&SEARCH, search_params, filter_expansion) }
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

impl SimpleProperties for SearchParameters {
    fn terms(&self) -> &[String] {
        &self.terms
    }

    fn terms_mut(&mut self) -> &mut Vec<String> {
        &mut self.terms
    }
}

impl ToFilterExpression for SearchParameters {
    fn to_filter_expression(&self) -> String {
        let mut terms = escape_terms(self.terms.clone()).collect::<Vec<_>>();

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
