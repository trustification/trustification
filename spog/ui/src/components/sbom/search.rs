use crate::{
    backend::{self, PackageService},
    components::search::*,
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
pub struct SbomSearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>>,

    pub mode: SearchPropertiesMode,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,

    #[prop_or_default]
    pub children: Children,
}

#[function_component(SbomSearch)]
pub fn sbom_search(props: &SbomSearchProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let config = use_config();

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
    } = use_standard_search::<DynamicSearchParameters, Packages>(props.mode.clone(), *total, filters.clone());

    let search = {
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

    total.set(search.data().and_then(|d| d.total));

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (props.callback.clone(), search.clone()),
    );

    // render

    let simple = search_params.is_simple();
    let onchange = use_callback(|data, text| text.set(data), text.clone());
    let managed = matches!(&props.mode, SearchPropertiesMode::Managed { .. });

    html!(
        <>

            <Grid>
                <GridItem cols={[2]}>
                    if managed {
                        <SimpleModeSwitch {simple} ontoggle={ontogglesimple} />
                    }
                </GridItem>

                <GridItem cols={[10]}>
                    <SearchToolbar
                        text={(*text).clone()}
                        {managed}
                        pagination={pagination.clone()}
                        total={*total}
                        children={props.toolbar_items.clone()}
                        {onset}
                        {onclear}
                        {onchange}
                        filter_input_state={filter_input_state.clone()}
                    />
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
