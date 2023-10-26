//! Unified search

use patternfly_yew::prelude::*;
use spog_ui_common::utils::count::count_tab_title;
use spog_ui_components::{
    advisory::{use_advisory_search, AdvisoryResult, AdvisorySearchControls},
    common::Visible,
    cve::{use_cve_search, CveResult, CveSearchControls},
    hooks::UseStandardSearch,
    packages::{use_package_search, PackagesResult},
    pagination::PaginationWrapped,
    sbom::{use_sbom_search, SbomResult, SbomSearchControls},
    search::{DynamicSearchParameters, SearchMode, SearchModeAction},
};
use std::ops::Deref;
use trustification_api::search::SearchResult;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TabIndex {
    Advisories,
    Sboms,
    SbomsByPackage,
    #[default]
    Cves,
    Packages,
}

#[derive(PartialEq, Properties)]
pub struct SearchProperties {
    pub terms: String,
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct PageState {
    pub terms: Vec<String>,
    pub tab: TabIndex,

    pub advisory: TabState,
    pub sbom: TabState,
    pub sbom_by_dependency: TabState,
    pub cve: TabState,
    pub package: TabState,
}

#[derive(Clone, Debug, Default, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TabState {
    pub pagination: PaginationControl,
    pub search_params: SearchMode<DynamicSearchParameters>,
}

#[function_component(Search)]
pub fn search(props: &SearchProperties) -> Html {
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

    let onclick = use_callback((text.clone(), search_terms.clone()), |_, (terms, search_terms)| {
        search_terms.set(split_terms(terms));
    });
    let onsubmit = use_callback((text.clone(), search_terms.clone()), |_, (terms, search_terms)| {
        search_terms.set(split_terms(terms));
    });

    // managing tabs

    let tab = use_state_eq(|| page_state.tab);
    let onselect = use_callback(tab.clone(), |index, tab| tab.set(index));

    // advisory search

    let advisory = use_unified_search(
        &page_state,
        |page_state| page_state.advisory.search_params.clone(),
        |page_state| page_state.advisory.pagination,
        use_advisory_search,
    );

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
    let sbom_by_dependency = use_unified_search(
        &page_state,
        |page_state| page_state.sbom_by_dependency.search_params.clone(),
        |page_state| page_state.sbom_by_dependency.pagination,
        |search_params, pagination, callback| {
            use_sbom_search(search_params, pagination, callback, |context| {
                format!("in:dependency ( {} )", context.search_params.as_str(&context.filters))
            })
        },
    );

    // CVE search

    let cve = use_unified_search(
        &page_state,
        |page_state| page_state.cve.search_params.clone(),
        |page_state| page_state.cve.pagination,
        use_cve_search,
    );

    // Package search

    let package = use_unified_search(
        &page_state,
        |page_state| page_state.package.search_params.clone(),
        |page_state| page_state.package.pagination,
        use_package_search,
    );

    // update search terms

    use_effect_with(
        (
            (*search_terms).clone(),
            advisory.search_params.clone(),
            sbom.search_params.clone(),
            sbom_by_dependency.search_params.clone(),
            cve.search_params.clone(),
            package.search_params.clone(),
        ),
        |(search_terms, advisory, sbom, sbom_by_dependency, cve, package)| {
            advisory.dispatch(SearchModeAction::SetSimpleTerms(search_terms.clone()));
            sbom.dispatch(SearchModeAction::SetSimpleTerms(search_terms.clone()));
            sbom_by_dependency.dispatch(SearchModeAction::SetSimpleTerms(search_terms.clone()));
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
                search_params: (*advisory.search_params).clone(),
            },
            sbom: TabState {
                pagination: **sbom.pagination,
                search_params: (*sbom.search_params).clone(),
            },
            sbom_by_dependency: TabState {
                pagination: **sbom_by_dependency.pagination,
                search_params: (*sbom_by_dependency.search_params).clone(),
            },
            cve: TabState {
                pagination: **cve.pagination,
                search_params: (*cve.search_params).clone(),
            },
            package: TabState {
                pagination: **package.pagination,
                search_params: (*package.search_params).clone(),
            },
        },
    );

    // render

    html!(
        <>
            <PageSection sticky={[PageSectionSticky::Top]} variant={PageSectionVariant::Light}>
                <Flex>
                    <FlexItem>
                        <Content>
                            <Title>{"Search Results"}</Title>
                        </Content>
                    </FlexItem>
                    <FlexItem modifiers={[FlexModifier::Align(Alignment::Right)]}>
                        <form {onsubmit}>
                            // needed to trigger submit when pressing enter in the search field
                            <input type="submit" hidden=true formmethod="dialog" />
                            <InputGroup>
                                <InputGroupItem>
                                    <TextInputGroup style="--pf-v5-c-text-input-group__text-input--MinWidth: 64ch;">
                                        <TextInputGroupMain
                                            id="search_terms"
                                            icon={Icon::Search}
                                            value={(*text).clone()}
                                            {onchange}
                                        />
                                    </TextInputGroup>
                                </InputGroupItem>
                                <InputGroupItem>
                                    <Button
                                        id="search"
                                        variant={ButtonVariant::Control}
                                        icon={Icon::ArrowRight}
                                        {onclick}
                                    />
                                </InputGroupItem>
                            </InputGroup>
                        </form>
                    </FlexItem>
                </Flex>
            </PageSection>

            <PageSection variant={PageSectionVariant::Default} fill={PageSectionFill::Fill}>

                <Grid gutter=true>
                    <GridItem cols={[2]}>
                        <div class="pf-v5-u-background-color-100">
                            <Visible visible={*tab == TabIndex::Advisories}>
                                <AdvisorySearchControls search_params={advisory.search_params.clone()} />
                            </Visible>
                            <Visible visible={*tab == TabIndex::Packages}>
                                <SbomSearchControls search_params={package.search_params.clone()} />
                            </Visible>
                            <Visible visible={*tab == TabIndex::Sboms}>
                                <SbomSearchControls search_params={sbom.search_params.clone()} />
                            </Visible>
                            <Visible visible={*tab == TabIndex::SbomsByPackage}>
                                <SbomSearchControls search_params={sbom_by_dependency.search_params.clone()} />
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
                            <Tab<TabIndex> index={TabIndex::Cves} title={count_tab_title("CVEs", &*cve.state)} />
                            <Tab<TabIndex> index={TabIndex::Packages} title={count_tab_title("Packages", &*package.state)} />
                            <Tab<TabIndex> index={TabIndex::Sboms} title={count_tab_title("Products and containers", &*sbom.state)} />
                            <Tab<TabIndex> index={TabIndex::Advisories} title={count_tab_title("Advisories", &*advisory.state)} />
                            // <Tab<TabIndex> index={TabIndex::SbomsByPackage} title={count_tab_title("SBOMs (by dependency)", &*sbom_by_dependency.state)} />
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
                            if *tab == TabIndex::SbomsByPackage {
                                <PaginationWrapped pagination={sbom_by_dependency.pagination} total={*sbom_by_dependency.total}>
                                    <SbomResult state={(*sbom_by_dependency.state).clone()} onsort={&sbom_by_dependency.onsort} />
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
    IS: FnOnce(&PageState) -> SearchMode<DynamicSearchParameters>,
    IP: FnOnce(&PageState) -> PaginationControl,
    FH: FnOnce(
        UseReducerHandle<SearchMode<DynamicSearchParameters>>,
        UsePagination,
        Callback<UseAsyncHandleDeps<SearchResult<R>, String>>,
    ) -> H,
    H: Hook<Output = UseStandardSearch>,
{
    let search_params = use_reducer_eq::<SearchMode<DynamicSearchParameters>, _>(|| init_search(page_state));
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
