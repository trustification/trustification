use crate::{
    hooks::{use_generic_search, UseStandardSearch},
    packages::PackagesResult,
    search::*,
};
use bombastic_model::packages::PackageInfo;
use patternfly_yew::prelude::*;
use spog_ui_backend::PackageInfoService;
use spog_ui_common::utils::pagination_to_offset;
use spog_ui_utils::config::use_config;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(PartialEq, Properties)]
pub struct PackageSearchControlsProperties {
    pub search_params: UseReducerHandle<SearchState<DynamicSearchParameters>>,
}

#[function_component(PackageSearchControls)]
pub fn packages_search_controls(props: &PackageSearchControlsProperties) -> Html {
    let config = use_config();
    let filters = use_memo((), |()| config.packages.filters.clone());

    let search_config = {
        use_memo((), move |()| {
            let (search, defaults) = convert_search(&filters);
            props.search_params.dispatch(SearchModeAction::ApplyDefault(defaults));
            search
        })
    };

    html!(
        <SimpleSearch search={search_config} search_params={props.search_params.clone()} />
    )
}

#[hook]
pub fn use_package_search(
    search_params: UseReducerHandle<SearchState<DynamicSearchParameters>>,
    pagination: UsePagination,
    callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<spog_model::prelude::PackageInfo>>>, String>>,
) -> UseStandardSearch {
    let config = use_config();
    use_generic_search::<PackageInfo, _, _, _, _>(
        search_params,
        pagination,
        callback,
        || config.packages.filters.clone(),
        |context| async move {
            let service = PackageInfoService::new(context.backend.clone(), context.access_token);
            service
                .search_packages(
                    &context.search_params.as_str(&context.filters),
                    &spog_ui_backend::SearchParameters {
                        offset: Some(pagination_to_offset(context.page, context.per_page)),
                        limit: Some(context.per_page),
                        ..Default::default()
                    },
                )
                .await
                .map(|result| result.map(Rc::new))
                .map_err(|err| err.to_string())
        },
    )
}

#[derive(PartialEq, Properties)]
pub struct PackageSearchProperties {
    pub query: Option<String>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
struct PageState {
    pagination: PaginationControl,
    search_params: HistorySearchState<DynamicSearchParameters>,
}

#[function_component(PackagesSearch)]
pub fn packages_search(props: &PackageSearchProperties) -> Html {
    let page_state = use_page_state(|| PageState {
        search_params: match props.query.as_ref().filter(|s| !s.is_empty()) {
            Some(terms) => SearchMode::Complex(terms.clone()),
            None => Default::default(),
        }
        .into(),
        ..Default::default()
    });

    let search_params = use_reducer_eq::<SearchState<DynamicSearchParameters>, _>(|| {
        SearchState::from(page_state.search_params.clone())
    });
    let total = use_state_eq(|| None);
    let pagination = use_pagination(*total, || page_state.pagination);
    let state = use_state_eq(UseAsyncState::default);
    let callback = use_callback(
        state.clone(),
        |state: UseAsyncHandleDeps<SearchResult<Rc<_>>, String>, search| {
            search.set((*state).clone());
        },
    );
    let search = use_package_search(search_params.clone(), pagination.clone(), callback);

    total.set(state.data().and_then(|d| d.total));

    let onsort = {
        use_callback(search_params.clone(), move |sort_by: (String, Order), search_params| {
            search_params.dispatch(SearchModeAction::SetSimpleSort(sort_by));
        })
    };

    // update page state

    use_page_state_update(
        page_state,
        PageState {
            pagination: **pagination,
            search_params: (*search_params).clone().into(),
        },
    );

    // render

    let simple = search.search_params.is_simple();
    let onchange = use_callback(search.text.clone(), |data, text| text.set(data));

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
                    <PackageSearchControls search_params={search.search_params} />
                </GridItem>

                <GridItem cols={[10]}>
                    <PackagesResult state={(*state).clone()} onsort={&onsort} />
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
