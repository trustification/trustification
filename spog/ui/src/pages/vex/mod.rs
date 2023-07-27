use crate::{
    backend::{self, Advisory},
    components::{
        advisory::{cat_label, tracking_status_str, CsafNotes, CsafProductInfo, CsafReferences, CsafVulnTable},
        common::{CardWrapper, NotFound, PageHeading},
        content::{SourceCode, UnknownContent},
        error::Error,
        severity::Severity,
    },
    hooks::use_backend,
};
use csaf::document::Category;
use humansize::{format_size, BINARY};
use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct VEXProperties {
    pub id: String,
}

#[function_component(VEX)]
pub fn vex(props: &VEXProperties) -> Html {
    let backend = use_backend();
    let info = use_async_with_cloned_deps(
        |(id, backend)| async move {
            backend::VexService::new(backend.clone())
                .get(id)
                .await
                .map(|result| result.map(backend::Advisory::parse).map(Rc::new))
        },
        (props.id.clone(), backend),
    );

    let (heading, content) = match &*info {
        UseAsyncState::Pending | UseAsyncState::Processing => (
            html!(<PageHeading subtitle="Advisory detail information">{ &props.id }</PageHeading>),
            html!(<PageSection fill={PageSectionFill::Fill}><Spinner/></PageSection>),
        ),
        UseAsyncState::Ready(Ok(None)) => (
            html!(<PageHeading sticky=false subtitle="Advisory detail information">{ &props.id } {" "} </PageHeading>),
            html!(<NotFound/>),
        ),
        UseAsyncState::Ready(Ok(Some(data))) => (
            html!(<PageHeading sticky=false subtitle="Advisory detail information">{ &props.id } {" "} </PageHeading>),
            html!(<Details vex={data.clone()}/> ),
        ),
        UseAsyncState::Ready(Err(err)) => (
            html!(<PageHeading subtitle="Advisory detail information">{ &props.id }</PageHeading>),
            html!(<PageSection fill={PageSectionFill::Fill}><Error err={err.to_string()} /></PageSection>),
        ),
    };

    html!(
        <>
            { heading }
            { content }
        </>
    )
}

#[derive(Clone, PartialEq, Properties)]
struct DetailsProps {
    vex: Rc<Advisory>,
}

#[function_component(Details)]
fn details(props: &DetailsProps) -> Html {
    let tab = use_state_eq(|| 0);
    let onselect = {
        let tab = tab.clone();
        Callback::from(move |index: usize| {
            tab.set(index);
        })
    };

    match &*props.vex {
        Advisory::Csaf { csaf, source } => {
            html!(
                <>
                    <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                        <Tabs inset={TabInset::Page} detached=true {onselect}>
                            <Tab label="Overview" />
                            <Tab label="Notes" />
                            <Tab label="Vulnerabilities" />
                            <Tab label="Source" />
                        </Tabs>
                    </PageSection>

                    <PageSection hidden={*tab != 0} fill={PageSectionFill::Fill}>
                        <Grid gutter=true>
                            <GridItem cols={[4]}>
                                <CardWrapper title="Overview">
                                    <DescriptionList>
                                        <DescriptionGroup term="Title">{ &csaf.document.title }</DescriptionGroup>
                                        <DescriptionGroup term="Category">{ match &csaf.document.category {
                                                Category::Base => "Base",
                                                Category::SecurityAdvisory => "Advisory",
                                                Category::Vex => "Vex",
                                                Category::Other(s) => s,
                                        } }</DescriptionGroup>
                                        if let Some(aggregate_severity) = &csaf.document.aggregate_severity {
                                            <DescriptionGroup term="Aggregate Severity">
                                                { match &aggregate_severity.namespace {
                                                    Some(namespace) => html!(
                                                        <Tooltip text={namespace.to_string()}>
                                                            <Severity severity={aggregate_severity.text.clone()} />
                                                        </Tooltip>
                                                    ),
                                                    None => html!(<Severity severity={aggregate_severity.text.clone()} />),
                                                }}
                                            </DescriptionGroup>
                                        }
                                        <DescriptionGroup term="Size">{ format_size(source.as_bytes().len(), BINARY) }</DescriptionGroup>
                                    </DescriptionList>
                                </CardWrapper>
                            </GridItem>

                            <GridItem cols={[4]}>
                                <CardWrapper title="Publisher">
                                    <DescriptionList>
                                        <DescriptionGroup term="Name">
                                            { &csaf.document.publisher.name } {" "}
                                            <Label label={cat_label(&csaf.document.publisher.category)} color={Color::Blue} />
                                        </DescriptionGroup>
                                        <DescriptionGroup term="Namespace">
                                            { csaf.document.publisher.namespace.to_string() }
                                        </DescriptionGroup>
                                        if let Some(contact_details) = &csaf.document.publisher.contact_details {
                                            <DescriptionGroup term="Contact Details">
                                                { &contact_details }
                                            </DescriptionGroup>
                                        }
                                        if let Some(issuing_authority) = &csaf.document.publisher.issuing_authority {
                                            <DescriptionGroup term="Issuing Authority">
                                                { &issuing_authority }
                                            </DescriptionGroup>
                                        }
                                    </DescriptionList>
                                </CardWrapper>
                            </GridItem>

                            <GridItem cols={[4]}>
                                <CardWrapper title="Tracking">
                                    <DescriptionList>
                                        <DescriptionGroup term="ID">
                                            { &csaf.document.tracking.id }
                                        </DescriptionGroup>
                                        <DescriptionGroup term="Status">
                                            { tracking_status_str(&csaf.document.tracking.status) }
                                        </DescriptionGroup>
                                        <DescriptionGroup term="Initial release date">
                                            { &csaf.document.tracking.initial_release_date }
                                        </DescriptionGroup>
                                        <DescriptionGroup term="Current release date">
                                            { &csaf.document.tracking.current_release_date }
                                        </DescriptionGroup>
                                    </DescriptionList>
                                </CardWrapper>
                            </GridItem>

                            <GridItem cols={[6]}>
                                <CsafReferences references={csaf.document.references.clone()} />
                            </GridItem>

                            <GridItem cols={[6]}>
                                <CardWrapper title="Product Info">
                                    <CsafProductInfo csaf={csaf.clone()} />
                                </CardWrapper>
                            </GridItem>
                        </Grid>
                    </PageSection>

                    <PageSection hidden={*tab != 1} fill={PageSectionFill::Fill}>
                        <Grid gutter=true>
                            if let Some(notes) = &csaf.document.notes {
                                <GridItem cols={[12]}>
                                    <CsafNotes notes={notes.clone()} />
                                </GridItem>
                            }
                        </Grid>
                    </PageSection>

                    <PageSection hidden={*tab != 2} fill={PageSectionFill::Fill}>
                        <CsafVulnTable expandable=true csaf={csaf.clone()} />
                    </PageSection>

                    <PageSection hidden={*tab != 3} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
                        <SourceCode source={source.clone()}/>
                    </PageSection>
                </>
            )
        }
        Advisory::Unknown(source) => {
            html!(
                <UnknownContent source={source.clone()}/>
            )
        }
    }
}
