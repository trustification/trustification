use crate::{
    backend::{PackageService, SearchOptions},
    components::search::*,
    hooks::{use_backend::use_backend, use_config, use_standard_search, UseStandardSearch},
    utils::pagination_to_offset,
};
use bombastic_model::prelude::Packages;
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
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
                    <SimpleSearch<DynamicSearchParameters> search={search_config} {search_params} />
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
