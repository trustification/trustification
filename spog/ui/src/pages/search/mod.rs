//! Unified search

pub mod search_input;

use crate::analytics::{ActionAnalytics, AnalyticEvents, ObjectNameAnalytics};
use patternfly_yew::prelude::*;
use search_input::SearchInput;
use spog_ui_common::utils::count::CountTabTitle;
use spog_ui_components::{
    advisory::{use_advisory_search, AdvisoryResult, AdvisorySearchControls},
    cve::{use_cve_search, CveResult, CveSearchControls},
    hooks::UseStandardSearch,
    packages::{use_package_search, PackageSearchControls, PackagesResult},
    pagination::PaginationWrapped,
    sbom::{use_sbom_search, SbomResult, SbomSearchControls},
    search::{DynamicSearchParameters, HistorySearchState, SearchModeAction, SearchState},
};
use spog_ui_utils::analytics::use_analytics;
use std::ops::Deref;
use trustification_api::search::SearchResult;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(
    Copy, Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize, strum::EnumString, strum::Display,
)]
#[strum(serialize_all = "camelCase")]
pub enum TabIndex {
    Advisories,
    #[default]
    Sboms,
    Cves,
    Packages,
}

#[derive(PartialEq, Properties)]
pub struct SearchProperties {
    /// the initial search terms
    pub terms: String,
}

/// The state of the page, stored in the history
#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PageState {
    pub terms: Vec<String>,
    pub tab: TabIndex,

    pub advisory: TabState,
    pub sbom: TabState,
    pub cve: TabState,
    pub package: TabState,
}

/// The state of a single tab, stored in the history
#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TabState {
    pub pagination: PaginationControl,
    pub search_params: HistorySearchState<DynamicSearchParameters>,
}

#[function_component(Search)]
pub fn search(props: &SearchProperties) -> Html {
    let analytics = use_analytics();

    // page state

    let page_state = use_page_state(|| PageState {
        terms: split_terms(&props.terms),
        ..Default::default()
    });

    // active search terms

    let search_terms = use_state_eq(|| page_state.terms.clone());

    // text in the input field

    let text = use_state_eq(|| page_state.terms.join(" "));
    let onchange = use_callback(text.clone(), |new_text, text| text.set(new_text));

    // events to activate the search terms

    let onsubmit = use_callback(
        (analytics.clone(), text.clone(), search_terms.clone()),
        |_, (analytics, terms, search_terms)| {
            analytics.track(AnalyticEvents {
                obj_name: ObjectNameAnalytics::SearchPage,
                action: ActionAnalytics::Search((**terms).clone()),
            });

            search_terms.set(split_terms(terms));
        },
    );

    // managing tabs

    let tab = use_state_eq(|| page_state.tab);
    let onselect = use_callback((analytics.clone(), tab.clone()), |index, (analytics, tab)| {
        analytics.track(AnalyticEvents {
            obj_name: ObjectNameAnalytics::SearchPage,
            action: ActionAnalytics::SelectTab(format!("{}", *tab.clone())),
        });

        tab.set(index)
    });

    // advisory search

    let advisory = use_unified_search(
        &page_state,
        |page_state| page_state.advisory.search_params.clone(),
        |page_state| page_state.advisory.pagination,
        use_advisory_search,
    );

    let advisory_count = (*advisory.state).data().and_then(|e| e.total);
    let advisory_is_processing = (*advisory.state).is_processing();

    // sbom search

    let sbom = use_unified_search(
        &page_state,
        |page_state| page_state.sbom.search_params.clone(),
        |page_state| page_state.sbom.pagination,
        |search_params, pagination, callback| {
            use_sbom_search(search_params, pagination, callback, |context| {
                context.search_params.as_str(&context.filters)
            })
        },
    );

    let sbom_count = (*sbom.state).data().and_then(|e| e.total);
    let sbom_is_processing = (*sbom.state).is_processing();

    // CVE search

    let cve = use_unified_search(
        &page_state,
        |page_state| page_state.cve.search_params.clone(),
        |page_state| page_state.cve.pagination,
        use_cve_search,
    );

    let cve_count = (*cve.state).data().and_then(|e| e.total);
    let cve_is_processing = (*cve.state).is_processing();

    // Package search

    let package = use_unified_search(
        &page_state,
        |page_state| page_state.package.search_params.clone(),
        |page_state| page_state.package.pagination,
        use_package_search,
    );

    let package_count = (*package.state).data().and_then(|e| e.total);
    let package_is_processing = (*package.state).is_processing();

    // update search terms

    use_effect_with(
        (
            (*search_terms).clone(),
            advisory.search_params.clone(),
            sbom.search_params.clone(),
            cve.search_params.clone(),
            package.search_params.clone(),
        ),
        |(search_terms, advisory, sbom, cve, package)| {
            advisory.dispatch(SearchModeAction::SetSimpleTerms(search_terms.clone()));
            sbom.dispatch(SearchModeAction::SetSimpleTerms(search_terms.clone()));
            cve.dispatch(SearchModeAction::SetSimpleTerms(search_terms.clone()));
            package.dispatch(SearchModeAction::SetSimpleTerms(search_terms.clone()));
        },
    );

    // update page state

    use_page_state_update(
        page_state,
        PageState {
            terms: (*search_terms).clone(),
            tab: *tab,
            advisory: TabState {
                pagination: **advisory.pagination,
                search_params: (*advisory.search_params).clone().into(),
            },
            sbom: TabState {
                pagination: **sbom.pagination,
                search_params: (*sbom.search_params).clone().into(),
            },
            cve: TabState {
                pagination: **cve.pagination,
                search_params: (*cve.search_params).clone().into(),
            },
            package: TabState {
                pagination: **package.pagination,
                search_params: (*package.search_params).clone().into(),
            },
        },
    );

    // render

    html!(
        <>
            <PageSection sticky={[PageSectionSticky::Top]} variant={PageSectionVariant::Light}>
                <Grid>
                    <GridItem cols={[2]}>
                        <Content>
                            <Title>{"Search Results"}</Title>
                        </Content>
                    </GridItem>
                    <GridItem offset={[4.lg(), 6.xl(), 8.xxl()]} cols={[10.all(), 8.lg(), 6.xl(), 4.xxl()]}>
                        <form {onsubmit}>
                            // needed to trigger submit when pressing enter in the search field
                            <input type="submit" hidden=true formmethod="dialog" />
                            <SearchInput {onchange}
                                submit_on_enter=true
                                initial_value={props.terms.clone()}
                            />
                        </form>
                    </GridItem>
                </Grid>
            </PageSection>

            <PageSection variant={PageSectionVariant::Default} fill={PageSectionFill::Fill}>

                <Grid gutter=true>
                    <GridItem cols={[2]}>
                        <div class="pf-v5-u-background-color-100">
                            <Visible visible={*tab == TabIndex::Advisories}>
                                <AdvisorySearchControls search_params={advisory.search_params.clone()} />
                            </Visible>
                            <Visible visible={*tab == TabIndex::Packages}>
                                <PackageSearchControls search_params={package.search_params.clone()} />
                            </Visible>
                            <Visible visible={*tab == TabIndex::Sboms}>
                                <SbomSearchControls search_params={sbom.search_params.clone()} />
                            </Visible>
                            <Visible visible={*tab == TabIndex::Cves}>
                                <CveSearchControls search_params={cve.search_params.clone()} />
                            </Visible>
                        </div>
                    </GridItem>

                    <GridItem cols={[10]}>
                        <Tabs<TabIndex>
                            inset={TabInset::Page}
                            detached=true
                            selected={*tab} {onselect}
                            r#box=true
                        >
                            <Tab<TabIndex> index={TabIndex::Sboms} title={html!(
                                <>
                                    <CountTabTitle title="SBOMs" count={sbom_count} processing={sbom_is_processing} />
                                    <Popover
                                        target={html!(
                                            <button class="pf-v5-c-button pf-m-plain pf-m-small" type="button" style="padding: 0px 0px 0px 5px;">
                                                <span class="pf-v5-c-tabs__item-action-icon">
                                                { Icon::QuestionCircle }
                                                </span>
                                            </button>
                                        )}
                                        body={html_nested!(
                                            <PopoverBody>{"Software Bill of Materials for Products and Containers."}</PopoverBody>
                                        )}
                                    />
                                </>
                            )}/>
                            <Tab<TabIndex> index={TabIndex::Packages} title={html!(<CountTabTitle title="Packages" count={package_count} processing={package_is_processing} />)} />
                            <Tab<TabIndex> index={TabIndex::Cves} title={html!(<CountTabTitle title="CVEs" count={cve_count} processing={cve_is_processing} />)} />
                            <Tab<TabIndex> index={TabIndex::Advisories} title={html!(<CountTabTitle title="Advisories" count={advisory_count} processing={advisory_is_processing} />)} />
                        </Tabs<TabIndex>>

                        <div class="pf-v5-u-background-color-100">
                            if *tab == TabIndex::Advisories {
                                <PaginationWrapped pagination={advisory.pagination} total={*advisory.total}>
                                    <AdvisoryResult state={(*advisory.state).clone()} onsort={&advisory.onsort} />
                                </PaginationWrapped>
                            }
                            if *tab == TabIndex::Packages {
                                <PaginationWrapped pagination={package.pagination} total={*package.total}>
                                    <PackagesResult state={(*package.state).clone()} onsort={&package.onsort} />
                                </PaginationWrapped>
                            }
                            if *tab == TabIndex::Sboms {
                                <PaginationWrapped pagination={sbom.pagination} total={*sbom.total}>
                                    <SbomResult state={(*sbom.state).clone()} onsort={&sbom.onsort} />
                                </PaginationWrapped>
                            }
                            if *tab == TabIndex::Cves {
                                <PaginationWrapped pagination={cve.pagination} total={*cve.total}>
                                    <CveResult state={(*cve.state).clone()} onsort={&cve.onsort} />
                                </PaginationWrapped>
                            }
                        </div>

                    </GridItem>
                </Grid>

            </PageSection>

        </>
    )
}

pub struct UseUnifiedSearch<R> {
    pub pagination: UsePagination,
    pub search: UseStandardSearch,
    pub total: UseStateHandle<Option<usize>>,
    pub state: UseStateHandle<UseAsyncState<SearchResult<R>, String>>,
    pub onsort: Callback<(String, Order)>,
}

impl<R> Deref for UseUnifiedSearch<R> {
    type Target = UseStandardSearch;

    fn deref(&self) -> &Self::Target {
        &self.search
    }
}

#[hook]
fn use_unified_search<R, IS, IP, FH, H>(
    page_state: &UsePageState<PageState>,
    init_search: IS,
    init_pagination: IP,
    use_hook: FH,
) -> UseUnifiedSearch<R>
where
    R: Clone + PartialEq + 'static,
    IS: FnOnce(&PageState) -> HistorySearchState<DynamicSearchParameters>,
    IP: FnOnce(&PageState) -> PaginationControl,
    FH: FnOnce(
        UseReducerHandle<SearchState<DynamicSearchParameters>>,
        UsePagination,
        Callback<UseAsyncHandleDeps<SearchResult<R>, String>>,
    ) -> H,
    H: Hook<Output = UseStandardSearch>,
{
    let search_params = use_reducer_eq::<SearchState<DynamicSearchParameters>, _>(|| init_search(page_state).into());
    let state = use_state_eq(UseAsyncState::default);
    let callback = use_callback(
        state.clone(),
        |state: UseAsyncHandleDeps<SearchResult<R>, String>, search| {
            search.set((*state).clone());
        },
    );
    let total = use_state_eq(|| None);
    total.set(state.data().and_then(|d| d.total));
    let pagination = use_pagination(*total, || init_pagination(page_state));
    let search = use_hook(search_params.clone(), pagination.clone(), callback);

    let onsort = use_callback(search_params.clone(), move |sort_by: (String, Order), search_params| {
        search_params.dispatch(SearchModeAction::SetSimpleSort(sort_by));
    });

    UseUnifiedSearch {
        pagination,
        search,
        total,
        state,
        onsort,
    }
}

fn split_terms(terms: &str) -> Vec<String> {
    terms.split(' ').map(ToString::to_string).collect()
}
