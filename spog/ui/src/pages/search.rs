//! Unified search

use crate::{
    components::{
        advisory::{use_advisory_search, AdvisoryResult, AdvisorySearchControls},
        common::Visible,
        sbom::use_sbom_search,
        sbom::{PackageResult, SbomSearchControls},
        search::*,
    },
    utils::count::count_tab_title,
};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(Copy, Clone, Eq, PartialEq)]
pub enum TabIndex {
    Advisories,
    Sboms,
}

#[derive(PartialEq, Properties)]
pub struct SearchProperties {
    pub terms: String,
}

#[function_component(Search)]
pub fn search(props: &SearchProperties) -> Html {
    // active search terms
    let search_terms = use_state_eq(|| props.terms.clone());

    // text in the input field
    let text = use_state_eq(|| props.terms.clone());
    let onchange = use_callback(|new_text, text| text.set(new_text), text.clone());

    let onclick = use_callback(
        |_, (terms, search_terms)| {
            search_terms.set((**terms).clone());
        },
        (text.clone(), search_terms.clone()),
    );
    let onsubmit = use_callback(
        |_, (terms, search_terms)| {
            search_terms.set((**terms).clone());
        },
        (text.clone(), search_terms.clone()),
    );

    let tab = use_state_eq(|| TabIndex::Advisories);
    let onselect = use_callback(|index, tab| tab.set(index), tab.clone());

    // advisory search

    let advisory_search = use_state_eq(UseAsyncState::default);
    let advisory_callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>, search| {
            search.set((*state).clone());
        },
        advisory_search.clone(),
    );
    let advisory = use_advisory_search(
        SearchPropertiesMode::Provided {
            terms: (*search_terms).clone(),
        },
        advisory_callback,
    );

    // sbom search

    let sbom_search = use_state_eq(UseAsyncState::default);
    let sbom_callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>, search| {
            search.set((*state).clone());
        },
        sbom_search.clone(),
    );
    let sbom = use_sbom_search(
        SearchPropertiesMode::Provided {
            terms: (*search_terms).clone(),
        },
        sbom_callback,
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
                                <PaginationWrapped pagination={advisory.pagination} total={*advisory.total}>
                                    <AdvisoryResult state={(*advisory_search).clone()} />
                                </PaginationWrapped>
                            }
                            if *tab == TabIndex::Sboms {
                                <PaginationWrapped pagination={sbom.pagination} total={*sbom.total}>
                                    <PackageResult state={(*sbom_search).clone()} />
                                </PaginationWrapped>
                            }
                        </div>

                    </GridItem>
                </Grid>

            </PageSection>

        </>
    )
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
