use csaf::document::Category;
use humansize::{format_size, BINARY};
use patternfly_yew::prelude::*;
use spog_ui_backend::{use_backend, Advisory, VexService};
use spog_ui_common::error::components::Error;
use spog_ui_components::{
    advisory::{cat_label, tracking_status_str, CsafNotes, CsafProductInfo, CsafReferences, CsafVulnTable},
    common::{CardWrapper, NotFound, PageHeading},
    content::{SourceCode, UnknownContent},
    severity::Severity,
};
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_oauth2::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct VEXProperties {
    pub id: String,
}

#[function_component(VEX)]
pub fn vex(props: &VEXProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let info = use_async_with_cloned_deps(
        |(id, backend)| async move {
            VexService::new(backend.clone(), access_token)
                .get(id)
                .await
                .map(|result| result.map(Advisory::parse).map(Rc::new))
        },
        (props.id.clone(), backend),
    );

    let (heading, content) = match &*info {
        UseAsyncState::Pending | UseAsyncState::Processing => (
            html!(<PageHeading subtitle="Advisory detail information">{ props.id.clone() }</PageHeading>),
            html!(<PageSection fill={PageSectionFill::Fill}><Spinner/></PageSection>),
        ),
        UseAsyncState::Ready(Ok(None)) => (
            html!(<PageHeading sticky=false subtitle="Advisory detail information">{ props.id.clone() } {" "} </PageHeading>),
            html!(<NotFound/>),
        ),
        UseAsyncState::Ready(Ok(Some(data))) => (
            html!(<PageHeading sticky=false subtitle="Advisory detail information">{ props.id.clone() } {" "} </PageHeading>),
            html!(<Details vex={data.clone()}/> ),
        ),
        UseAsyncState::Ready(Err(err)) => (
            html!(<PageHeading subtitle="Advisory detail information">{ props.id.clone() }</PageHeading>),
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
    #[derive(Copy, Clone, Eq, PartialEq)]
    enum TabIndex {
        Overview,
        Notes,
        Vulnerabilities,
        Source,
    }

    let tab = use_state_eq(|| TabIndex::Overview);
    let onselect = use_callback(tab.clone(), |index, tab| tab.set(index));

    match &*props.vex {
        Advisory::Csaf { csaf, source } => {
            html!(
                <>
                    <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                        <Tabs<TabIndex> inset={TabInset::Page} detached=true selected={*tab} {onselect}>
                            <Tab<TabIndex> index={TabIndex::Overview} title="Overview" />
                            <Tab<TabIndex> index={TabIndex::Notes} title="Notes" />
                            <Tab<TabIndex> index={TabIndex::Vulnerabilities} title="Vulnerabilities" />
                            <Tab<TabIndex> index={TabIndex::Source} title="Source" />
                        </Tabs<TabIndex>>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Overview} fill={PageSectionFill::Fill}>
                        <Grid gutter=true>
                            <GridItem cols={[4]}>
                                <CardWrapper title="Overview">
                                    <DescriptionList>
                                        <DescriptionGroup term="Title">{ csaf.document.title.clone() }</DescriptionGroup>
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
                                                { contact_details.clone() }
                                            </DescriptionGroup>
                                        }
                                        if let Some(issuing_authority) = &csaf.document.publisher.issuing_authority {
                                            <DescriptionGroup term="Issuing Authority">
                                                { issuing_authority.clone() }
                                            </DescriptionGroup>
                                        }
                                    </DescriptionList>
                                </CardWrapper>
                            </GridItem>

                            <GridItem cols={[4]}>
                                <CardWrapper title="Tracking">
                                    <DescriptionList>
                                        <DescriptionGroup term="ID">
                                            { csaf.document.tracking.id.clone() }
                                        </DescriptionGroup>
                                        <DescriptionGroup term="Status">
                                            { tracking_status_str(&csaf.document.tracking.status) }
                                        </DescriptionGroup>
                                        <DescriptionGroup term="Initial release date">
                                            { csaf.document.tracking.initial_release_date.to_string() }
                                        </DescriptionGroup>
                                        <DescriptionGroup term="Current release date">
                                            { csaf.document.tracking.current_release_date.to_string() }
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

                    <PageSection hidden={*tab != TabIndex::Notes} fill={PageSectionFill::Fill}>
                        <Grid gutter=true>
                            if let Some(notes) = &csaf.document.notes {
                                <GridItem cols={[12]}>
                                    <CsafNotes notes={notes.clone()} />
                                </GridItem>
                            }
                        </Grid>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Vulnerabilities} fill={PageSectionFill::Fill}>
                        <CsafVulnTable expandable=true csaf={csaf.clone()} />
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Source} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
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
