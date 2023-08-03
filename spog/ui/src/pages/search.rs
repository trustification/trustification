//! Unified search

use crate::components::{
    advisory::{AdvisoryResult, AdvisorySearch, SearchMode},
    sbom::{PackageResult, SbomSearch},
};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

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

    let tab = use_state_eq(|| 0);
    let onselect = use_callback(|index, tab| tab.set(index), tab.clone());

    // advisory search

    let advisory_search = use_state_eq(UseAsyncState::default);
    let advisory_callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>, search| {
            search.set((*state).clone());
        },
        advisory_search.clone(),
    );

    // sbom search

    let sbom_search = use_state_eq(UseAsyncState::default);
    let sbom_callback = use_callback(
        |state: UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>, search| {
            search.set((*state).clone());
        },
        sbom_search.clone(),
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
                        <Form {onsubmit}>
                            // needed to trigger submit when pressing enter in the search field
                            <input type="submit" hidden=true formmethod="dialog" />
                            <InputGroup>
                                <InputGroupItem>
                                    <TextInputGroup>
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
                        </Form>
                    </FlexItem>
                </Flex>
            </PageSection>

            <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                <Tabs inset={TabInset::Page} detached=true {onselect}>
                    <Tab label="Advisories" />
                    <Tab label="SBOMs"/>
                </Tabs>
            </PageSection>

            <PageSection hidden={*tab != 0} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>

                <AdvisorySearch callback={advisory_callback} mode={SearchMode::Provided}>
                    <AdvisoryResult state={(*advisory_search).clone()} />
                </AdvisorySearch>

            </PageSection>

            <PageSection hidden={*tab != 1} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>

                <SbomSearch callback={sbom_callback} mode={SearchMode::Provided}>
                    <PackageResult state={(*sbom_search).clone()} />
                </SbomSearch>

            </PageSection>

        </>
    )
}
