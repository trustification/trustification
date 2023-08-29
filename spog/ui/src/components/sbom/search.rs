use crate::{
    backend::{self, PackageService},
    components::{sbom::PackageResult, search::*},
    hooks::{use_backend, use_config, use_standard_search, UseStandardSearch},
    utils::pagination_to_offset,
};
use bombastic_model::prelude::Packages;
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_oauth2::prelude::*;

#[derive(PartialEq, Properties)]
pub struct SbomSearchControlsProperties {
    pub search_params: UseStateHandle<SearchMode<DynamicSearchParameters>>,
}

#[function_component(SbomSearchControls)]
pub fn sbom_search_controls(props: &SbomSearchControlsProperties) -> Html {
    let config = use_config();
    let filters = use_memo(|()| config.bombastic.filters.clone(), ());
    let search_config = use_memo(|()| convert_search(&filters), ());

    html!(
        <SimpleSearch<DynamicSearchParameters> search={search_config} search_params={props.search_params.clone()} />
    )
}

#[hook]
pub fn use_sbom_search(
    search_params: UseStateHandle<SearchMode<DynamicSearchParameters>>,
    pagination: UsePagination,
    callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>>,
) -> UseStandardSearch {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let config = use_config();
    let filters = use_memo(|()| config.bombastic.filters.clone(), ());

    let search = use_standard_search::<Packages>(search_params.clone(), filters.clone());

    let search_op = {
        let filters = filters.clone();
        use_async_with_cloned_deps(
            move |(search_params, page, per_page)| async move {
                let service = PackageService::new(backend.clone(), access_token);
                service
                    .search_packages(
                        &search_params.as_str(&filters),
                        &backend::SearchParameters {
                            offset: Some(pagination_to_offset(page, per_page)),
                            limit: Some(per_page),
                            ..Default::default()
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            ((*search_params).clone(), pagination.page, pagination.per_page),
        )
    };

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (callback.clone(), search_op.clone()),
    );

    search
}

#[derive(PartialEq, Properties)]
pub struct SbomSearchProperties {
    pub query: Option<String>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct PageState {
    pagination: PaginationControl,
    search_params: SearchMode<DynamicSearchParameters>,
}

#[function_component(SbomSearch)]
pub fn sbom_search(props: &SbomSearchProperties) -> Html {
    let page_state = use_page_state(|| PageState {
        search_params: match props.query.as_ref().filter(|s| !s.is_empty()) {
            Some(terms) => SearchMode::Complex(terms.clone()),
            None => Default::default(),
        },
        ..Default::default()
    });

    let search_params = use_state_eq::<SearchMode<DynamicSearchParameters>, _>(|| page_state.search_params.clone());
    let total = use_state_eq(|| None);
    let pagination = use_pagination(*total, || page_state.pagination);
    let state = use_state_eq(UseAsyncState::default);
    let callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<Rc<_>>, String>, search| {
            search.set((*state).clone());
        },
        state.clone(),
    );
    let search = use_sbom_search(search_params.clone(), pagination.clone(), callback);

    total.set(state.data().and_then(|d| d.total));

    // update page state

    use_page_state_update(
        page_state,
        PageState {
            pagination: **pagination,
            search_params: (*search_params).clone(),
        },
    );

    // render

    let simple = search.search_params.is_simple();
    let onchange = use_callback(|data, text| text.set(data), search.text.clone());

    html!(
        <>

            <Grid>
                <GridItem cols={[2]}>
                    <div style="height: 100%; display: flex;">
                        <SimpleModeSwitch {simple} ontoggle={search.ontogglesimple} />
                    </div>
                </GridItem>

                <GridItem cols={[10]}>
                    <SearchToolbar
                        text={(*search.text).clone()}
                        pagination={pagination.clone()}
                        total={*total}
                        children={props.toolbar_items.clone()}
                        onset={search.onset}
                        onclear={search.onclear}
                        {onchange}
                        filter_input_state={search.filter_input_state.clone()}
                    />
                </GridItem>

                <GridItem cols={[2]}>
                    <SbomSearchControls search_params={search.search_params} />
                </GridItem>

                <GridItem cols={[10]}>
                    <PackageResult state={(*state).clone()} />
                </GridItem>

            </Grid>

            <SimplePagination
                pagination={pagination}
                total={*total}
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
