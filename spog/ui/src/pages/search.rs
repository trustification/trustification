//! Unified search

use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use spog_ui_common::utils::count::count_tab_title;
use spog_ui_components::{
    advisory::{use_advisory_search, AdvisoryResult, AdvisorySearchControls},
    common::Visible,
    hooks::UseStandardSearch,
    sbom::{use_sbom_search, SbomResult, SbomSearchControls},
    search::{DynamicSearchParameters, SearchMode},
};
use std::ops::Deref;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TabIndex {
    #[default]
    Advisories,
    Sboms,
    SbomsByPackage,
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
    let onchange = use_callback(|new_text, text| text.set(new_text), text.clone());

    // events to activate the search terms

    let onclick = use_callback(
        |_, (terms, search_terms)| {
            search_terms.set(split_terms(terms));
        },
        (text.clone(), search_terms.clone()),
    );
    let onsubmit = use_callback(
        |_, (terms, search_terms)| {
            search_terms.set(split_terms(terms));
        },
        (text.clone(), search_terms.clone()),
    );

    // managing tabs

    let tab = use_state_eq(|| page_state.tab);
    let onselect = use_callback(|index, tab| tab.set(index), tab.clone());

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

    // update search terms

    {
        use_effect_with_deps(
            |(search_terms, advisory, sbom, sbom_by_dependency)| {
                advisory.set(advisory.set_simple_terms(search_terms.clone()));
                sbom.set(sbom.set_simple_terms(search_terms.clone()));
                sbom_by_dependency.set(sbom_by_dependency.set_simple_terms(search_terms.clone()));
            },
            (
                (*search_terms).clone(),
                advisory.search_params.clone(),
                sbom.search_params.clone(),
                sbom_by_dependency.search_params.clone(),
            ),
        );
    }

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
                                            icon={Icon::Search}
                                            value={(*text).clone()}
                                            {onchange}
                                        />
                                    </TextInputGroup>
                                </InputGroupItem>
                                <InputGroupItem>
                                    <Button
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
                            <Visible visible={*tab == TabIndex::Sboms}>
                                <SbomSearchControls search_params={sbom.search_params.clone()} />
                            </Visible>
                            <Visible visible={*tab == TabIndex::SbomsByPackage}>
                                <SbomSearchControls search_params={sbom_by_dependency.search_params.clone()} />
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
                            <Tab<TabIndex> index={TabIndex::Advisories} title={count_tab_title("Advisories", &*advisory.state)} />
                            <Tab<TabIndex> index={TabIndex::Sboms} title={count_tab_title("SBOMs", &*sbom.state)} />
                            <Tab<TabIndex> index={TabIndex::SbomsByPackage} title={count_tab_title("SBOMs (by dependency)", &*sbom_by_dependency.state)} />
                        </Tabs<TabIndex>>

                        <div class="pf-v5-u-background-color-100">
                            if *tab == TabIndex::Advisories {
                                <PaginationWrapped pagination={advisory.pagination} total={*advisory.total}>
                                    <AdvisoryResult state={(*advisory.state).clone()} onsort={&advisory.onsort} />
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
    pub onsort: Callback<(String, bool)>,
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
        UseStateHandle<SearchMode<DynamicSearchParameters>>,
        UsePagination,
        Callback<UseAsyncHandleDeps<SearchResult<R>, String>>,
    ) -> H,
    H: Hook<Output = UseStandardSearch>,
{
    let search_params = use_state_eq::<SearchMode<DynamicSearchParameters>, _>(|| init_search(page_state));
    let state = use_state_eq(UseAsyncState::default);
    let callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<R>, String>, search| {
            search.set((*state).clone());
        },
        state.clone(),
    );
    let total = use_state_eq(|| None);
    total.set(state.data().and_then(|d| d.total));
    let pagination = use_pagination(*total, || init_pagination(page_state));
    let search = use_hook(search_params.clone(), pagination.clone(), callback);

    let onsort = {
        use_callback(
            move |sort_by: (String, bool), search_params| {
                if let SearchMode::Simple(simple) = &**search_params {
                    let mut simple = simple.clone();
                    simple.set_sort_by(sort_by);
                    search_params.set(SearchMode::Simple(simple));
                };
            },
            search_params.clone(),
        )
    };

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

#[derive(PartialEq, Properties)]
pub struct PaginationWrappedProperties {
    pub children: Children,
    pub pagination: UsePagination,
    pub total: Option<usize>,
}

#[function_component(PaginationWrapped)]
pub fn pagination_wrapped(props: &PaginationWrappedProperties) -> Html {
    html!(
        <>
            <div class="pf-v5-u-p-sm">
                <SimplePagination
                    pagination={props.pagination.clone()}
                    total={props.total}
                />
            </div>
            { for props.children.iter() }
            <div class="pf-v5-u-p-sm">
                <SimplePagination
                    pagination={props.pagination.clone()}
                    total={props.total}
                    position={PaginationPosition::Bottom}
                />
            </div>
        </>
    )
}
