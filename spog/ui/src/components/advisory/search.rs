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

#[hook]
pub fn use_advisory_search(
    mode: SearchPropertiesMode,
    callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>>,
) -> UseStandardSearch {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let total = use_state_eq(|| None);

    let config = use_config();
    let filters = use_memo(|()| config.vexination.filters.clone(), ());

    let search_params = use_state_eq::<SearchMode<DynamicSearchParameters>, _>(Default::default);
    let pagination = use_pagination(*total, Default::default);

    let search = use_standard_search::<Vulnerabilities>(
        search_params.clone(),
        pagination.clone(),
        mode,
        filters.clone(),
        total.clone(),
    );

    let search_op = {
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

    total.set(search_op.data().and_then(|d| d.total));

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (callback.clone(), search_op.clone()),
    );

    search
}

#[function_component(AdvisorySearch)]
pub fn advisory_search(props: &AdvisorySearchProperties) -> Html {
    let search = use_advisory_search(props.mode.clone(), props.callback.clone());

    // render

    let simple = search.search_params.is_simple();
    let onchange = use_callback(|data, text| text.set(data), search.text.clone());
    let managed = matches!(&props.mode, SearchPropertiesMode::Managed { .. });

    html!(
        <>

            <Grid>
                <GridItem cols={[2]}>
                    if managed {
                        <div style="height: 100%; display: flex;">
                            <SimpleModeSwitch {simple} ontoggle={search.ontogglesimple} />
                        </div>
                    }
                </GridItem>

                <GridItem cols={[10]}>
                    <SearchToolbar
                        text={(*search.text).clone()}
                        {managed}
                        pagination={search.pagination.clone()}
                        total={*search.total}
                        children={props.toolbar_items.clone()}
                        onset={search.onset}
                        onclear={search.onclear}
                        {onchange}
                        filter_input_state={search.filter_input_state.clone()}
                    />
                </GridItem>

                <GridItem cols={[2]}>
                    <AdvisorySearchControls search_params={search.search_params}/>
                </GridItem>

                <GridItem cols={[10]}>
                    { for props.children.iter() }
                </GridItem>

            </Grid>

            <SimplePagination
                pagination={search.pagination}
                total={*search.total}
                position={PaginationPosition::Bottom}
            />

        </>
    )
}
