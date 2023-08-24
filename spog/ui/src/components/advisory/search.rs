use crate::{
    backend::{self, VexService},
    components::search::*,
    hooks::{use_backend, use_config, use_standard_search, UseStandardSearch},
    utils::pagination_to_offset,
};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
use vexination_model::prelude::Vulnerabilities;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_oauth2::prelude::*;

#[derive(PartialEq, Properties)]
pub struct AdvisorySearchControlsProperties {
    pub search_params: UseStateHandle<SearchMode<DynamicSearchParameters>>,
}

#[function_component(AdvisorySearchControls)]
pub fn advisory_search_controls(props: &AdvisorySearchControlsProperties) -> Html {
    let config = use_config();
    let filters = use_memo(|()| config.vexination.filters.clone(), ());
    let search_config = use_memo(|()| convert_search(&filters), ());

    html!(
        <SimpleSearch<DynamicSearchParameters> search={search_config} search_params={props.search_params.clone()} />
    )
}

#[derive(PartialEq, Properties)]
pub struct AdvisorySearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>>,

    pub mode: SearchPropertiesMode,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,

    #[prop_or_default]
    pub children: Children,
}

#[function_component(AdvisorySearch)]
pub fn advisory_search(props: &AdvisorySearchProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let total = use_state_eq(|| None);

    let config = use_config();
    let filters = use_memo(|()| config.vexination.filters.clone(), ());

    let UseStandardSearch {
        search_params,
        pagination,
        filter_input_state,
        onclear,
        onset,
        ontogglesimple,
        text,
    } = use_standard_search::<DynamicSearchParameters, Vulnerabilities>(props.mode.clone(), *total, filters.clone());

    let search = {
        let filters = filters.clone();
        use_async_with_cloned_deps(
            move |(search_params, page, per_page)| async move {
                let service = VexService::new(backend.clone(), access_token);
                service
                    .search_advisories(
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
                        <div style="height: 100%; display: flex;">
                            <SimpleModeSwitch {simple} ontoggle={ontogglesimple} />
                        </div>
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
                    <AdvisorySearchControls {search_params}/>
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
