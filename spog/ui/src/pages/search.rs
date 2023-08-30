//! Unified search

use crate::{
    components::{
        advisory::{use_advisory_search, AdvisoryResult, AdvisorySearchControls},
        common::Visible,
        sbom::{use_sbom_search, SbomResult, SbomSearchControls},
        search::{DynamicSearchParameters, SearchMode},
    },
    utils::count::count_tab_title,
};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(Copy, Clone, Debug, Default, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum TabIndex {
    #[default]
    Advisories,
    Sboms,
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

    let advisory_search_params =
        use_state_eq::<SearchMode<DynamicSearchParameters>, _>(|| page_state.advisory.search_params.clone());
    let advisory_search = use_state_eq(UseAsyncState::default);
    let advisory_callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>, search| {
            search.set((*state).clone());
        },
        advisory_search.clone(),
    );
    let advisory_total = use_state_eq(|| None);
    advisory_total.set(advisory_search.data().and_then(|d| d.total));
    let advisory_pagination = use_pagination(*advisory_total, || page_state.advisory.pagination);
    let advisory = use_advisory_search(
        advisory_search_params.clone(),
        advisory_pagination.clone(),
        advisory_callback,
    );

    // sbom search

    let sbom_search_params =
        use_state_eq::<SearchMode<DynamicSearchParameters>, _>(|| page_state.sbom.search_params.clone());
    let sbom_search = use_state_eq(UseAsyncState::default);
    let sbom_callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>, search| {
            search.set((*state).clone());
        },
        sbom_search.clone(),
    );
    let sbom_total = use_state_eq(|| None);
    sbom_total.set(sbom_search.data().and_then(|d| d.total));
    let sbom_pagination = use_pagination(*sbom_total, || page_state.sbom.pagination);
    let sbom = use_sbom_search(sbom_search_params.clone(), sbom_pagination.clone(), sbom_callback);

    // update search terms

    {
        use_effect_with_deps(
            |(search_terms, advisory, sbom)| {
                advisory.set(advisory.set_simple_terms(search_terms.clone()));
                sbom.set(sbom.set_simple_terms(search_terms.clone()));
            },
            (
                (*search_terms).clone(),
                advisory.search_params.clone(),
                sbom.search_params.clone(),
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
                pagination: **advisory_pagination,
                search_params: (*advisory_search_params).clone(),
            },
            sbom: TabState {
                pagination: **sbom_pagination,
                search_params: (*sbom_search_params).clone(),
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
                        </div>
                    </GridItem>

                    <GridItem cols={[10]}>
                        <Tabs<TabIndex>
                            inset={TabInset::Page}
                            detached=true
                            selected={*tab} {onselect}
                            r#box=true
                        >
                            <Tab<TabIndex> index={TabIndex::Advisories} title={count_tab_title("Advisories", &*advisory_search)} />
                            <Tab<TabIndex> index={TabIndex::Sboms} title={count_tab_title("SBOMs", &*sbom_search)} />
                        </Tabs<TabIndex>>

                        <div class="pf-v5-u-background-color-100">
                            if *tab == TabIndex::Advisories {
                                <PaginationWrapped pagination={advisory_pagination} total={*advisory_total}>
                                    <AdvisoryResult state={(*advisory_search).clone()} />
                                </PaginationWrapped>
                            }
                            if *tab == TabIndex::Sboms {
                                <PaginationWrapped pagination={sbom_pagination} total={*sbom_total}>
                                    <SbomResult state={(*sbom_search).clone()} />
                                </PaginationWrapped>
                            }
                        </div>

                    </GridItem>
                </Grid>

            </PageSection>

        </>
    )
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
