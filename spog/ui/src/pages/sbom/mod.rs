use crate::{
    backend,
    components::{
        common::{NotFound, PageHeading},
        content::{Technical, UnknownContent},
        error::Error,
        spdx::*,
    },
    hooks::use_backend,
    model,
};
use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_oauth2::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct SBOMProperties {
    pub id: String,
}

#[function_component(SBOM)]
pub fn sbom(props: &SBOMProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let info = use_async_with_cloned_deps(
        |(id, backend)| async move {
            backend::SBOMService::new(backend.clone(), access_token)
                .get(id)
                .await
                .map(|result| result.map(model::SBOM::parse).map(Rc::new))
        },
        (props.id.clone(), backend),
    );

    let (heading, content) = match &*info {
        UseAsyncState::Pending | UseAsyncState::Processing => (
            html!(<PageHeading subtitle="SBOM detail information">{ &props.id }</PageHeading>),
            html!(<PageSection fill={PageSectionFill::Fill}><Spinner/></PageSection>),
        ),
        UseAsyncState::Ready(Ok(None)) => (
            html!(<PageHeading sticky=false subtitle="SBOM detail information">{ &props.id } {" "} </PageHeading>),
            html!(<NotFound/>),
        ),
        UseAsyncState::Ready(Ok(Some(data))) => (
            html!(<PageHeading sticky=false subtitle="SBOM detail information">{ &props.id } {" "} <Label label={data.type_name()} color={Color::Blue} /> </PageHeading>),
            html!(<Details sbom={data.clone()}/> ),
        ),
        UseAsyncState::Ready(Err(err)) => (
            html!(<PageHeading subtitle="SBOM detail information">{ &props.id }</PageHeading>),
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
    sbom: Rc<model::SBOM>,
}

#[function_component(Details)]
fn details(props: &DetailsProps) -> Html {
    #[derive(Copy, Clone, Eq, PartialEq)]
    enum TabIndex {
        Overview,
        Packages,
        Source,
    }

    let tab = use_state_eq(|| TabIndex::Overview);
    let onselect = use_callback(|index, tab| tab.set(index), tab.clone());

    match &*props.sbom {
        model::SBOM::SPDX { bom, source } => {
            html!(
                <>
                    <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                        <Tabs<TabIndex> inset={TabInset::Page} detached=true selected={*tab} {onselect}>
                            <Tab<TabIndex> index={TabIndex::Overview} title="Overview" />
                            <Tab<TabIndex> index={TabIndex::Packages} title="Packages" />
                            <Tab<TabIndex> index={TabIndex::Source} title="Source" />
                        </Tabs<TabIndex>>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Overview} fill={PageSectionFill::Fill}>
                        <Grid gutter=true>
                            <GridItem cols={[4]}>{spdx_meta(bom)}</GridItem>
                            <GridItem cols={[2]}>{spdx_creator(bom)}</GridItem>
                            <GridItem cols={[2]}>{spdx_stats(source.as_bytes().len(), bom)}</GridItem>
                            <GridItem cols={[4]}>{spdx_main(bom)}</GridItem>
                        </Grid>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Packages} fill={PageSectionFill::Fill}>
                        // FIXME: use .clone() instead
                        <SpdxPackages bom={Rc::new(serde_json::from_str(source).unwrap())}/>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Source} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
                        <CodeBlock>
                            <CodeBlockCode> { source.clone() } </CodeBlockCode>
                        </CodeBlock>
                    </PageSection>
                </>
            )
        }
        model::SBOM::CycloneDX { bom: _, source } => {
            html!(
                <>
                    <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                        <Tabs<TabIndex> inset={TabInset::Page} detached=true selected={*tab} {onselect}>
                            <Tab<TabIndex> index={TabIndex::Overview} title="Overview" />
                            <Tab<TabIndex> index={TabIndex::Source} title="Source" />
                        </Tabs<TabIndex>>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Overview} fill={PageSectionFill::Fill}>
                        <Grid gutter=true>
                            <GridItem cols={[2]}><Technical size={source.as_bytes().len()}/></GridItem>
                        </Grid>
                    </PageSection>

                    <PageSection hidden={*tab != TabIndex::Source} fill={PageSectionFill::Fill}>
                        <CodeBlock>
                            <CodeBlockCode> { source.clone() } </CodeBlockCode>
                        </CodeBlock>
                    </PageSection>
                </>
            )
        }
        model::SBOM::Unknown(source) => {
            html!(
                <UnknownContent source={source.clone()} />
            )
        }
    }
}
