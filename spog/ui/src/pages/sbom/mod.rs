use crate::{
    backend,
    components::{common::PageHeading, error::Error},
    hooks::use_backend::use_backend,
    model,
};
use cyclonedx_bom::prelude::Bom;
use patternfly_yew::prelude::*;
use spdx_rs::models::{PackageInformation, SPDX};
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct SBOMProperties {
    pub id: String,
}

#[function_component(SBOM)]
pub fn sbom(props: &SBOMProperties) -> Html {
    let backend = use_backend();
    let info = use_async_with_cloned_deps(
        |(id, backend)| async move {
            backend::SBOMService::new(backend.clone())
                .get(id)
                .await
                .map(crate::model::SBOM::parse)
                .map(Rc::new)
        },
        (props.id.clone(), backend.clone()),
    );

    let (heading, content) = match &*info {
        UseAsyncState::Pending | UseAsyncState::Processing => (
            html!(<PageHeading subtitle="SBOM detail information">{ &props.id }</PageHeading>),
            html!(<Spinner/>),
        ),
        UseAsyncState::Ready(Ok(data)) => (
            html!(<PageHeading subtitle="SBOM detail information">{ &props.id } {" "} <Label label={data.type_name()} color={Color::Blue} /> </PageHeading>),
            html!(<Details sbom={data.clone()}/> ),
        ),
        UseAsyncState::Ready(Err(err)) => (
            html!(<PageHeading subtitle="SBOM detail information">{ &props.id }</PageHeading>),
            html!(<Error err={err.to_string()} />),
        ),
    };

    html!(
        <>
            { heading }
            <PageSection fill={PageSectionFill::Fill}>
                { content }
            </PageSection>
        </>
    )
}

#[derive(Clone, PartialEq, Properties)]
struct DetailsProps {
    sbom: Rc<model::SBOM>,
}

#[function_component(Details)]
fn details(props: &DetailsProps) -> Html {
    match &*props.sbom {
        model::SBOM::SPDX { bom, source } => {
            html!(
                <Tabs>
                    <Tab label="Overview">
                        <Grid gutter=true>
                            <GridItem cols={[4]}>{spdx_meta(bom)}</GridItem>
                            <GridItem cols={[2]}>{spdx_creator(bom)}</GridItem>
                        </Grid>
                    </Tab>
                    <Tab label="Packages">
                        <SpdxPackages packages={
                            {
                                let mut packages = bom.package_information.clone();
                                packages.sort_unstable_by(|a,b| {
                                    a.package_name.cmp(&b.package_name)
                                });
                                Rc::new(packages)
                            }

                        } />
                    </Tab>
                    <Tab label="Source">
                        <CodeBlock>
                            <CodeBlockCode> { source.clone() } </CodeBlockCode>
                        </CodeBlock>
                    </Tab>
                </Tabs>
            )
        }
        model::SBOM::CycloneDX { bom, source } => {
            html!(
                <Tabs>
                    <Tab label="Overview">
                    </Tab>
                    <Tab label="Source">
                        <CodeBlock>
                            <CodeBlockCode> { source.clone() } </CodeBlockCode>
                        </CodeBlock>
                    </Tab>
                </Tabs>
            )
        }
        model::SBOM::Unknown(data) => {
            html!(
                <CodeBlock>
                    <CodeBlockCode> { data } </CodeBlockCode>
                </CodeBlock>
            )
        }
    }
}

fn spdx_creator(bom: &SPDX) -> Html {
    let title = html!(<Title>{"Creation"}</Title>);

    html!(
        <Card {title}>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Created">{ &bom.document_creation_information.creation_info.created.to_string() }</DescriptionGroup>
                    if let Some(info) = &bom.document_creation_information.creation_info.license_list_version {
                        <DescriptionGroup term="License List Version">{ &info.to_string() }</DescriptionGroup>
                    }
                    {
                        match bom.document_creation_information.creation_info.creators.len() {
                            0 => html!(),
                            1 => {
                                // we can be sure to have one
                                html!(
                                    <DescriptionGroup term="Creator">
                                        { bom.document_creation_information.creation_info.creators[0].clone() }
                                    </DescriptionGroup>
                                )
                            },
                            _ => html! (
                                <DescriptionGroup term="Creators">
                                    <List>
                                        { for bom.document_creation_information.creation_info.creators.iter().map(Html::from) }
                                    </List>
                                </DescriptionGroup>
                            )
                        }
                    }
                </DescriptionList>
            </CardBody>
            { bom.document_creation_information.creation_info.creator_comment.as_ref().map(|comment|{
                html_nested!(<CardBody> { comment } </CardBody>)
            })}
        </Card>
    )
}

fn spdx_meta(bom: &SPDX) -> Html {
    let title = html!(<Title>{"Metadata"}</Title>);

    html!(
        <Card {title}>
            <CardBody>
                <DescriptionList>
                    <DescriptionGroup term="Name">{ &bom.document_creation_information.document_name }</DescriptionGroup>
                    <DescriptionGroup term="ID">{ &bom.document_creation_information.spdx_identifier }</DescriptionGroup>
                    <DescriptionGroup term="Namespace">{ &bom.document_creation_information.spdx_document_namespace }</DescriptionGroup>
                    <DescriptionGroup term="SPDX Version">{ &bom.document_creation_information.spdx_version }</DescriptionGroup>
                    <DescriptionGroup term="Data License">{ &bom.document_creation_information.data_license }</DescriptionGroup>
                </DescriptionList>
            </CardBody>
            { bom.document_creation_information.document_comment.as_ref().map(|comment|{
                html_nested!(<CardBody> { comment } </CardBody>)
            })}
        </Card>
    )
}

#[derive(PartialEq, Properties)]
struct SpdxPackagesProperties {
    packages: Rc<Vec<PackageInformation>>,
}

#[function_component(SpdxPackages)]
fn spdx_packages(props: &SpdxPackagesProperties) -> Html {
    #[derive(Clone, Eq, PartialEq)]
    enum Column {
        Name,
        Version,
    }

    impl TableEntryRenderer<Column> for PackageInformation {
        fn render_cell(&self, context: &CellContext<'_, Column>) -> Cell {
            match context.column {
                Column::Name => html!(&self.package_name),
                Column::Version => html!(self.package_version.clone().unwrap_or_default()),
            }
            .into()
        }
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Name} label="Name" />
            <TableColumn<Column> index={Column::Version} label="Version" />
        </TableHeader<Column>>
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(props.packages.clone()));

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<PackageInformation>>>
            mode={TableMode::Compact}
            {header}
            {entries}
            {onexpand}
        />

    )
}
