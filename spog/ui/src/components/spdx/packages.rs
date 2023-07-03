use crate::utils::OrNone;
use patternfly_yew::prelude::*;
use spdx_rs::models::{PackageInformation, Relationship, SPDX};
use std::collections::HashMap;
use std::rc::Rc;
use yew::prelude::*;

/// render the external packages
pub fn spdx_external_references(package: &PackageInformation) -> Html {
    html!(
        <List>
            { for package
                .external_reference
                .iter()
                .map(|e| {
                    html!( <>
                        {&e.reference_locator} { " " }
                        <Label label={format!("{:?}", e.reference_category)} color={Color::Blue} /> { " " }
                        <Label label={format!("{}", e.reference_type)} color={Color::Grey} />
                    </> )
                })
            }
        </List>
    )
}

pub fn spdx_relationship_entry(packages: &HashMap<String, PackageInformation>, rel: &Relationship, id: &str) -> Html {
    html!(<>
        { OrNone(packages.get(id).map(spdx_package_list_entry)) }
        {" "}
        <Label compact=true label={rel.relationship_type.as_ref().to_string()} />
    </>)
}

pub fn spdx_package_list_entry(package: &PackageInformation) -> Html {
    match &package.package_version {
        Some(version) => html!(
                <Tooltip text={version.clone()}>
                    { &package.package_name }
                </Tooltip>
        ),
        None => {
            html!(&package.package_name)
        }
    }
}

pub fn render_single_details(
    package: &PackageInformation,
    packages: &HashMap<String, PackageInformation>,
    relations: &Vec<Relationship>,
) -> Vec<Span> {
    let outgoing = relations
        .iter()
        .filter(|rel| rel.related_spdx_element == package.package_spdx_identifier)
        .collect::<Vec<_>>();
    let incoming = relations
        .iter()
        .filter(|rel| rel.spdx_element_id == package.package_spdx_identifier)
        .collect::<Vec<_>>();

    let content = html!(
        <Grid gutter=true>
            <GridItem cols={[4]}>
                <Card plain=true title={html!(<Title>{"Information"}</Title>)}>
                    <CardBody>
                        <DescriptionList>
                            <DescriptionGroup term="Download">{ &package.package_download_location }</DescriptionGroup>
                            <DescriptionGroup term="Copyright">{ &package.copyright_text }</DescriptionGroup>
                            <DescriptionGroup term="License (declared)">{ &package.declared_license }</DescriptionGroup>
                            <DescriptionGroup term="License (concluded)">{ &package.concluded_license }</DescriptionGroup>
                        </DescriptionList>
                    </CardBody>
                </Card>
            </GridItem>

            <GridItem cols={[4]}>
                <Card plain=true title={html!(<Title>{"External References"}</Title>)}>
                    <CardBody>
                        { spdx_external_references(&package) }
                    </CardBody>
                </Card>
            </GridItem>

            <GridItem cols={[4]}>
                <Card plain=true title={html!(<Title>{"Relationships"}</Title>)}>
                    { if !outgoing.is_empty() {
                        Some(html_nested!(<CardBody>
                            <Title level={Level::H3}>{"Outgoing"}</Title>
                            <List r#type={ListType::Basic}>
                                { for outgoing.into_iter().map(|rel|spdx_relationship_entry(&packages, rel, &rel.spdx_element_id))}
                            </List>
                        </CardBody>))
                    } else { None } }
                    { if !incoming.is_empty() {
                        Some(html_nested!(<CardBody>
                            <Title level={Level::H3}>{"Incoming"}</Title>
                            <List r#type={ListType::Basic}>
                                { for incoming.into_iter().map(|rel|spdx_relationship_entry(&packages, rel, &rel.related_spdx_element))}
                            </List>
                        </CardBody>))
                    } else { None } }
                </Card>
            </GridItem>
        </Grid>
    );

    vec![Span::max(content)]
}

#[derive(PartialEq, Properties)]
pub struct SpdxPackagesProperties {
    pub bom: Rc<SPDX>,
}

#[function_component(SpdxPackages)]
pub fn spdx_packages(props: &SpdxPackagesProperties) -> Html {
    #[derive(Clone, Eq, PartialEq)]
    enum Column {
        Name,
        Version,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct PackageWrapper {
        package: PackageInformation,
        relations: Rc<Vec<Relationship>>,
        packages: Rc<HashMap<String, PackageInformation>>,
    }

    impl TableEntryRenderer<Column> for PackageWrapper {
        fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
            match context.column {
                Column::Name => html!(&self.package.package_name),
                Column::Version => html!(self.package.package_version.clone().unwrap_or_default()),
            }
            .into()
        }

        fn render_details(&self) -> Vec<Span> {
            render_single_details(&self.package, &self.packages, &self.relations)
        }
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Name} label="Name" />
            <TableColumn<Column> index={Column::Version} label="Version" />
        </TableHeader<Column>>
    );

    let package_map = use_memo(
        |bom| {
            bom.package_information
                .iter()
                .map(|p| (p.package_spdx_identifier.clone(), p.clone()))
                .collect::<HashMap<_, _>>()
        },
        props.bom.clone(),
    );

    let offset = use_state_eq(|| 0);
    let limit = use_state_eq(|| 10);

    let filter = use_state_eq(String::new);

    let filtered_packages = {
        let offset = offset.clone();
        let limit = limit.clone();
        use_memo(
            move |(bom, filter)| {
                let mut packages = bom
                    .package_information
                    .clone()
                    .into_iter()
                    // apply filter
                    .filter(|p| filter.is_empty() || p.package_name.contains(filter))
                    .collect::<Vec<_>>();

                // we need to sort after filtering, as paging requires a sorted list
                packages.sort_unstable_by(|a, b| a.package_name.cmp(&b.package_name));

                // try to cap last page, only apply once
                if *offset > packages.len() {
                    if *limit > packages.len() {
                        offset.set(0);
                    } else {
                        offset.set(packages.len() - *limit);
                    }
                }

                // return result
                packages
            },
            (props.bom.clone(), (*filter).clone()),
        )
    };

    // total entries must be based on the filtered list
    let total_entries = filtered_packages.len();

    let entries = use_memo(
        |(bom, filtered_packages, package_map, offset, limit)| {
            let relations = Rc::new(bom.relationships.clone());
            filtered_packages
                .iter()
                // apply pagination window
                .skip(*offset)
                .take(*limit)
                // map
                .map(|package| PackageWrapper {
                    package: (*package).clone(),
                    relations: relations.clone(),
                    packages: package_map.clone(),
                })
                .collect::<Vec<_>>()
        },
        (
            props.bom.clone(),
            filtered_packages.clone(),
            package_map,
            *offset,
            *limit,
        ),
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    // FIXME: if the following is missing, expansion is broken, figure out "why"
    let onexpand = onexpand.reform(|(key, state)| (key, state));

    let limit_callback = {
        let limit = limit.clone();
        Callback::from(move |number| limit.set(number))
    };

    let nav_callback = {
        let offset = offset.clone();
        let limit = *limit;
        Callback::from(move |page: Navigation| {
            let o = match page {
                Navigation::First => 0,
                Navigation::Last => ((total_entries - 1) / limit) * limit,
                Navigation::Previous => *offset - limit,
                Navigation::Next => *offset + limit,
                Navigation::Page(n) => (n - 1) * limit,
            };
            offset.set(o);
        })
    };

    let onclearfilter = {
        let filter = filter.clone();
        Callback::from(move |_| filter.set(String::new()))
    };

    let onsetfilter = {
        let filter = filter.clone();
        Callback::from(move |value: String| filter.set(value.trim().to_string()))
    };

    html!(
        <>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem r#type={ToolbarItemType::SearchFilter}>
                        <TextInputGroup>
                            <TextInputGroupMain
                                placeholder="Filter"
                                icon={Icon::Search}
                                value={(*filter).clone()}
                                oninput={onsetfilter}
                            />
                            if !filter.is_empty() {
                                <TextInputGroupUtilities>
                                    <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclearfilter}/>
                                </TextInputGroupUtilities>
                            }
                        </TextInputGroup>
                    </ToolbarItem>

                    <ToolbarItem r#type={ToolbarItemType::Pagination}>
                        <Pagination
                            {total_entries}
                            offset={*offset}
                            entries_per_page_choices={vec![5, 10, 25, 50]}
                            selected_choice={*limit}
                            onlimit={&limit_callback}
                            onnavigation={&nav_callback}
                        />
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>

            <Table<Column, UseTableData<Column, MemoizedTableModel<PackageWrapper>>>
                mode={TableMode::CompactExpandable}
                {header}
                {entries}
                {onexpand}
            />

            <Pagination
                {total_entries}
                offset={*offset}
                entries_per_page_choices={vec![5, 10, 25, 50]}
                selected_choice={*limit}
                onlimit={&limit_callback}
                onnavigation={&nav_callback}
                position={PaginationPosition::Bottom}
            />
        </>
    )
}
