use super::{get_purl, spdx_external_references, spdx_package_list_entry};
use itertools::Itertools;
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use spdx_rs::models::{PackageInformation, Relationship, SPDX};
use spog_ui_common::utils::{highlight::highlight, OrNone};
use spog_ui_navigation::AppRoute;
use std::cell::RefCell;
use std::collections::{hash_map, BTreeMap, BTreeSet, HashMap, HashSet};
use std::rc::Rc;
use yew::prelude::*;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties)]
pub struct SpdxPackagesProperties {
    pub bom: Rc<SPDX>,
}

/// get the base version of a PURL, without qualifiers
fn make_base(purl: PackageUrl<'static>) -> PackageUrl<'static> {
    struct Options {
        with_namespace: bool,
        with_version: bool,
        with_subpath: bool,
    }

    fn perform(purl: PackageUrl, options: Options) -> Result<PackageUrl<'static>, packageurl::Error> {
        let mut result = PackageUrl::new(purl.ty().to_string(), purl.name().to_string())?;

        if options.with_namespace {
            if let Some(namespace) = purl.namespace() {
                result.with_namespace(namespace.to_string());
            }
        }

        if options.with_version {
            if let Some(version) = purl.version() {
                result.with_version(version.to_string());
            }
        }

        if options.with_subpath {
            if let Some(subpath) = purl.subpath() {
                result.with_subpath(subpath.to_string())?;
            }
        }

        Ok(result)
    }

    perform(
        purl.clone(),
        Options {
            with_version: false,
            with_namespace: true,
            with_subpath: true,
        },
    )
    .unwrap_or(purl)
}

#[function_component(SpdxPackages)]
pub fn spdx_packages(props: &SpdxPackagesProperties) -> Html {
    #[derive(Clone, Eq, PartialEq)]
    enum Column {
        Name,
        Versions,
        Qualifiers,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct PackageWrapper {
        filter: Rc<RefCell<String>>,
        base: PackageBase,
        relations: Rc<Vec<Relationship>>,
        all_packages: Rc<HashMap<String, PackageInformation>>,
    }

    #[derive(Clone, Debug, PartialEq)]
    enum PackageBase {
        Purl {
            /// Base part of the PURL
            base: PackageUrl<'static>,
            /// All packages belonging to this PURL
            packages: Vec<PackageInformation>,
            /// Versions for all packages
            versions: BTreeSet<String>,
            /// Qualifiers for all packages
            qualifiers: BTreeMap<String, BTreeSet<String>>,
        },
        Plain {
            package: PackageInformation,
        },
    }

    impl PackageBase {
        pub fn name(&self) -> &str {
            match self {
                PackageBase::Purl { base, .. } => base.name(),
                PackageBase::Plain { package } => &package.package_name,
            }
        }
    }

    impl TableEntryRenderer<Column> for PackageWrapper {
        fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
            match &self.base {
                PackageBase::Plain { package } => match context.column {
                    Column::Name => highlight(&package.package_name, &self.filter.borrow()).into(),
                    Column::Versions => Cell::from(html!(package.package_version.clone().unwrap_or_default()))
                        .text_modifier(TextModifier::Truncate),
                    Column::Qualifiers => html!().into(),
                },
                PackageBase::Purl {
                    base,
                    qualifiers,
                    versions,
                    ..
                } => match context.column {
                    Column::Name => html!(<>
                        <Link<AppRoute>
                            target={AppRoute::Package{id: base.to_string()}}
                        >
                            { highlight(base.name(), &self.filter.borrow()) }
                            if let Some(namespace) = base.namespace() {
                                { " / " } { highlight(namespace, &self.filter.borrow()) }
                            }
                        </Link<AppRoute>>
                        {" "}
                        <Label compact=true label={base.ty().to_string()} color={Color::Blue} />
                    </>)
                    .into(),
                    Column::Versions => {
                        Cell::from(html!(versions.iter().join(", "))).text_modifier(TextModifier::Truncate)
                    }
                    Column::Qualifiers => html!(
                        { for qualifiers.iter().flat_map(|(k,v)| {
                            let k = k.clone();
                            v.iter().map(move |v| {
                                html!(<><Label label={format!("{k}: {v}")} />{" "}</>)
                            })
                        }) }
                    )
                    .into(),
                },
            }
        }

        fn render_details(&self) -> Vec<Span> {
            match &self.base {
                PackageBase::Plain { package } => render_single_details(package, &self.all_packages, &self.relations),
                PackageBase::Purl {
                    base,
                    packages,
                    versions,
                    qualifiers,
                } => {
                    let content = html!(<>
                        <Grid gutter=true>
                            <GridItem cols={[4]}>
                                <Card plain=true title={html!(<Title>{"Details"}</Title>)}>
                                    <CardBody>
                                        <DescriptionList>
                                            <DescriptionGroup term="Base Package"><code>{base.to_string()}</code></DescriptionGroup>
                                        </DescriptionList>
                                    </CardBody>
                                </Card>
                            </GridItem>

                            <GridItem cols={[4]}>
                                <Card plain=true title={html!(<Title>{"Qualifiers"}</Title>)}>
                                    <CardBody>
                                        <DescriptionList mode={[DescriptionListMode::Horizontal]}>
                                        { for qualifiers.iter().map(|(k,v)| {
                                            html!(<>
                                                <DescriptionGroup term={k.clone()}>
                                                    { for v.iter().map(|v|{
                                                        html!(<><Label label={v.clone()}/> {" "}</>)
                                                    })}
                                                </DescriptionGroup>
                                            </>)
                                        })}
                                        </DescriptionList>
                                    </CardBody>
                                </Card>
                            </GridItem>

                            <GridItem cols={[4]}>
                                <Card plain=true title={html!(<Title>{"Versions"}</Title>)}>
                                    <CardBody>
                                        <List r#type={ListType::Basic}>
                                            { for versions.iter().map(Html::from) }
                                        </List>
                                    </CardBody>
                                </Card>
                            </GridItem>

                            <GridItem cols={[4]}>
                                <Card plain=true title={html!(<Title>{"Packages"}</Title>)}>
                                    <CardBody>
                                        <List r#type={ListType::Basic}>
                                            { for packages.iter().map(spdx_package_list_entry)}
                                        </List>
                                    </CardBody>
                                </Card>
                            </GridItem>
                        </Grid>
                    </>);
                    vec![Span::max(content)]
                }
            }
        }
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> width={ColumnWidth::Percent(30)} index={Column::Name} label="Name" />
            <TableColumn<Column> width={ColumnWidth::Percent(20)} index={Column::Versions} label="Versions" />
            <TableColumn<Column> width={ColumnWidth::Percent(50)} index={Column::Qualifiers} label="Qualifiers" />
        </TableHeader<Column>>
    );

    let package_map = use_memo(props.bom.clone(), |bom| {
        bom.package_information
            .iter()
            .map(|p| (p.package_spdx_identifier.clone(), p.clone()))
            .collect::<HashMap<_, _>>()
    });

    let package_filter_string = use_mut_ref(String::default);

    // convert from SBOM to package list collapsed by base PURL with qualifiers
    let packages = {
        let package_filter_string = package_filter_string.clone();
        use_memo((props.bom.clone(), package_map), |(bom, package_map)| {
            let relations = Rc::new(bom.relationships.clone());
            let mut result = Vec::with_capacity(bom.package_information.len());
            let mut base_map = HashMap::new();

            let mut duplicates = HashSet::<&str>::new();

            struct PurlMap {
                /// base purl
                base: PackageUrl<'static>,
                packages: Vec<(PackageUrl<'static>, PackageInformation)>,
            }

            for package in &bom.package_information {
                if !duplicates.insert(&package.package_spdx_identifier) {
                    continue;
                }

                match get_purl(package) {
                    Some(purl) => {
                        let base = make_base(purl.clone());
                        let base_str = base.to_string();
                        match base_map.entry(base_str) {
                            hash_map::Entry::Vacant(entry) => {
                                entry.insert(PurlMap {
                                    base,
                                    packages: vec![(purl, package.clone())],
                                });
                            }
                            hash_map::Entry::Occupied(mut entry) => {
                                entry.get_mut().packages.push((purl, package.clone()));
                            }
                        }
                    }
                    None => {
                        result.push(PackageWrapper {
                            base: PackageBase::Plain {
                                package: package.clone(),
                            },
                            relations: relations.clone(),
                            all_packages: package_map.clone(),
                            filter: package_filter_string.clone(),
                        });
                    }
                };
            }

            for PurlMap { base, packages } in base_map.into_values() {
                let mut qualifiers = BTreeMap::<String, BTreeSet<String>>::new();
                let mut versions = BTreeSet::<String>::new();
                let mut result_packages = Vec::with_capacity(packages.len());

                for (purl, package) in packages {
                    for (k, v) in purl.qualifiers() {
                        qualifiers.entry(k.to_string()).or_default().insert(v.to_string());
                    }

                    if let Some(version) = &purl.version() {
                        versions.insert(version.to_string());
                    }

                    result_packages.push(package);
                }

                result.push(PackageWrapper {
                    base: PackageBase::Purl {
                        base,
                        packages: result_packages,
                        qualifiers,
                        versions,
                    },
                    relations: relations.clone(),
                    all_packages: package_map.clone(),
                    filter: package_filter_string.clone(),
                })
            }

            result.sort_unstable_by(|a, b| a.base.name().cmp(b.base.name()));

            result
        })
    };

    let offset = use_state_eq(|| 0);
    let limit = use_state_eq(|| 10);

    let filter = use_state_eq(String::new);

    let filtered_packages = {
        let offset = offset.clone();
        let limit = limit.clone();
        use_memo((packages, (*filter).clone()), move |(packages, filter)| {
            let packages = packages
                .iter()
                // apply filter
                .filter(|p| {
                    filter.is_empty() || {
                        match &p.base {
                            PackageBase::Plain { package } => package.package_name.contains(filter),
                            // FIXME: consider caching to_string
                            PackageBase::Purl { base, .. } => {
                                base.name().contains(filter)
                                    || base.namespace().map(|s| s.contains(filter)).unwrap_or_default()
                            }
                        }
                    }
                })
                // clone and collect
                .cloned()
                .collect::<Vec<_>>();

            // try to cap last page, only apply once
            if *offset > packages.len() {
                if *limit > packages.len() {
                    offset.set(0);
                } else {
                    offset.set(packages.len() - *limit);
                }
            }

            // also update the filter value
            *package_filter_string.borrow_mut() = filter.clone();

            // return result
            packages
        })
    };

    // total entries must be based on the filtered list
    let total_entries = filtered_packages.len();

    // page from the filtered entries
    let entries = use_memo(
        (filtered_packages, *offset, *limit),
        |(filtered_packages, offset, limit)| {
            filtered_packages
                .iter()
                // apply pagination window
                .skip(*offset)
                .take(*limit)
                .cloned()
                .collect::<Vec<_>>()
        },
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

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
                                onchange={onsetfilter}
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

pub fn render_single_details(
    package: &PackageInformation,
    packages: &HashMap<String, PackageInformation>,
    relations: &[Relationship],
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
                            <DescriptionGroup term="Download">{ package.package_download_location.clone() }</DescriptionGroup>
                            if let Some(copright_text) = &package.copyright_text {
                                <DescriptionGroup term="Copyright">{ copright_text.clone() }</DescriptionGroup>
                            }
                            if let Some(declared_license) = &package.declared_license {
                                <DescriptionGroup term="License (declared)">{ declared_license.to_string() }</DescriptionGroup>
                            }
                            if let Some(concluded_license) = &package.concluded_license {
                                <DescriptionGroup term="License (concluded)">{ concluded_license.to_string() }</DescriptionGroup>
                            }
                        </DescriptionList>
                    </CardBody>
                </Card>
            </GridItem>

            <GridItem cols={[4]}>
                <Card plain=true title={html!(<Title>{"External References"}</Title>)}>
                    <CardBody>
                        { spdx_external_references(package) }
                    </CardBody>
                </Card>
            </GridItem>

            <GridItem cols={[4]}>
                <Card plain=true title={html!(<Title>{"Relationships"}</Title>)}>
                    { if !outgoing.is_empty() {
                        Some(html_nested!(<CardBody>
                            <Title level={Level::H3}>{"Outgoing"}</Title>
                            <List r#type={ListType::Basic}>
                                { for outgoing.into_iter().map(|rel|spdx_relationship_entry(packages, rel, &rel.spdx_element_id))}
                            </List>
                        </CardBody>))
                    } else { None } }
                    { if !incoming.is_empty() {
                        Some(html_nested!(<CardBody>
                            <Title level={Level::H3}>{"Incoming"}</Title>
                            <List r#type={ListType::Basic}>
                                { for incoming.into_iter().map(|rel|spdx_relationship_entry(packages, rel, &rel.related_spdx_element))}
                            </List>
                        </CardBody>))
                    } else { None } }
                </Card>
            </GridItem>
        </Grid>
    );

    vec![Span::max(content)]
}

pub fn spdx_relationship_entry(packages: &HashMap<String, PackageInformation>, rel: &Relationship, id: &str) -> Html {
    html!(<>
        { OrNone(packages.get(id).map(spdx_package_list_entry)) }
        {" "}
        <Label compact=true label={rel.relationship_type.as_ref().to_string()} />
    </>)
}
