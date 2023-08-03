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

#[derive(Clone, PartialEq, Eq)]
pub enum SearchMode {
    Managed { query: Option<String> },
    Provided,
}

#[derive(PartialEq, Properties)]
pub struct AdvisorySearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>>,

    pub mode: SearchMode,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,

    #[prop_or_default]
    pub children: Children,
}

impl AdvisorySearchProperties {
    fn props_query(&self) -> Option<String> {
        match &self.mode {
            SearchMode::Managed { query } => query.clone(),
            _ => None,
        }
    }
}

#[function_component(AdvisorySearch)]
pub fn advisory_search(props: &AdvisorySearchProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let config = use_config();
    let total = use_state_eq(|| None);

    let filters = use_memo(|()| config.vexination.filters.clone(), ());
    let search_config = use_memo(|()| convert_search(&filters), ());

    let UseStandardSearch {
        search_params,
        pagination,
        filter_input_state,
        onclear,
        onset,
        ontogglesimple,
        text,
    } = use_standard_search::<DynamicSearchParameters, Vulnerabilities>(props.props_query(), *total, filters.clone());

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
    let managed = matches!(&props.mode, SearchMode::Managed { .. });

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
