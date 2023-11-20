mod cve;

use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use spog_ui_components::{cvss::CvssScore, pagination::PaginationWrapped, time::Date};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::str::FromStr;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct DetailsProps {
    pub sbom: Rc<spog_model::prelude::SbomReport>,
}

#[function_component(Details)]
pub fn details(props: &DetailsProps) -> Html {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Column {
        Id,
        Description,
        Cvss,
        AffectedPackages,
        Published,
        Updated,
    }

    #[derive(Clone, PartialEq)]
    struct Entry {
        vuln: SbomReportVulnerability,
        packages: Rc<Vec<AffectedPackage>>,
    }

    impl TableEntryRenderer<Column> for Entry {
        fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
            match context.column {
                Column::Id => Cell::new(html!(self.vuln.id.clone())).text_modifier(TextModifier::NoWrap),
                Column::Description => html!({ for self.vuln.description.clone() }).into(),
                Column::Cvss => html!(
                    <>
                        if let Some(score) = self.vuln.score("mitre") {
                            <CvssScore cvss={score} />
                        }
                    </>
                )
                .into(),
                Column::AffectedPackages => {
                    let rems: usize = self.packages.iter().map(|p| p.1.remediations.len()).sum();
                    html!(
                        <>
                            { self.packages.len() }
                            if rems > 0 {
                                {" / "}
                                { rems }
                            }
                        </>
                    )
                    .into()
                }
                Column::Published => Cell::from(html!(if let Some(timestamp) = self.vuln.published {
                    <Date {timestamp} />
                }))
                .text_modifier(TextModifier::NoWrap),
                Column::Updated => Cell::from(html!(if let Some(timestamp) = self.vuln.updated {
                    <Date {timestamp} />
                }))
                .text_modifier(TextModifier::NoWrap),
            }
        }

        fn render_column_details(&self, column: &Column) -> Vec<Span> {
            let content = match column {
                Column::Id => {
                    html!(
                        <cve::Details id={self.vuln.id.clone()} />
                    )
                }
                Column::AffectedPackages => {
                    html!(<AffectedPackages
                            packages={self.packages.clone()}
                        />)
                }
                _ => html!(),
            };
            vec![Span::max(content)]
        }
    }

    let sort_by = use_state_eq(|| TableHeaderSortBy::ascending(Column::Id));
    let onsort = use_callback(sort_by.clone(), |value, sort_by| sort_by.set(value));

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Id} label="Id" width={ColumnWidth::FitContent} expandable=true sortby={*sort_by} onsort={onsort.clone()} />
            <TableColumn<Column> index={Column::Description} label="Description" width={ColumnWidth::WidthMax} />
            <TableColumn<Column> index={Column::Cvss} label="CVSS" width={ColumnWidth::Percent(15)} sortby={*sort_by} onsort={onsort.clone()} />
            <TableColumn<Column> index={Column::AffectedPackages} label="Affected dependencies" width={ColumnWidth::FitContent} expandable=true sortby={*sort_by} onsort={onsort.clone()} />
            <TableColumn<Column> index={Column::Published} label="Published" width={ColumnWidth::FitContent} sortby={*sort_by} onsort={onsort.clone()} />
            <TableColumn<Column> index={Column::Updated} label="Updated" width={ColumnWidth::FitContent} sortby={*sort_by} onsort={onsort.clone()} />
        </TableHeader<Column>>
    );

    let entries = use_memo((props.sbom.clone(), *sort_by), |(sbom, sort_by)| {
        let backtraces = Rc::new(sbom.backtraces.clone());
        let mut result = sbom
            .details
            .iter()
            .map(|vuln| {
                let packages = Rc::new(build_packages(&vuln.affected_packages, backtraces.clone()));
                Entry {
                    vuln: vuln.clone(),
                    packages,
                }
            })
            .collect::<Vec<_>>();

        result.sort_by(|a, b| {
            let result = match sort_by.index {
                Column::Cvss => a
                    .vuln
                    .score("mitre")
                    .partial_cmp(&b.vuln.score("mitre"))
                    .unwrap_or(Ordering::Equal),
                Column::AffectedPackages => a.vuln.affected_packages.len().cmp(&b.vuln.affected_packages.len()),
                Column::Published => a.vuln.published.cmp(&b.vuln.published),
                Column::Updated => a.vuln.updated.cmp(&b.vuln.updated),
                _ => a.vuln.id.cmp(&b.vuln.id),
            };

            match sort_by.order {
                Order::Ascending => result,
                Order::Descending => result.reverse(),
            }
        });

        result
    });

    let total = entries.len();
    let pagination = use_pagination(Some(total), Default::default);

    // page from the filtered entries
    let entries = use_memo((entries, pagination.control), |(entries, control)| {
        let offset = control.per_page * control.page;
        let limit = control.per_page;
        entries
            .iter()
            // apply pagination window
            .skip(offset)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
    });

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    match total {
        0 => html!(),
        _ => html!(
            <div class="pf-v5-u-background-color-100">
                <PaginationWrapped {pagination} {total}>
                    <Table<Column, UseTableData<Column, MemoizedTableModel<Entry>>>
                        {header}
                        {entries}
                        {onexpand}
                        mode={TableMode::Expandable}
                    />
                </PaginationWrapped>
            </div>
        ),
    }
}

fn build_packages<'a>(
    packages: impl IntoIterator<Item = (&'a String, &'a Vec<Remediation>)>,
    backtraces: Rc<BTreeMap<String, BTreeSet<Backtrace>>>,
) -> Vec<AffectedPackage> {
    let mut result = BTreeMap::<PackageKey, PackageValue>::new();

    for (purl, rems) in packages
        .into_iter()
        .filter_map(|(purl, rem)| Some((PackageUrl::from_str(purl).ok()?, rem)))
    {
        let key = PackageKey::new(&purl);
        let value = result.entry(key).or_insert_with(|| PackageValue {
            backtraces: backtraces.clone(),
            qualifiers: Default::default(),
            remediations: Default::default(),
        });
        for (k, v) in purl.qualifiers() {
            let qe = value.qualifiers.entry(k.to_string()).or_default();
            qe.insert(v.to_string());
        }
        // FIXME: need to reduce
        value.remediations.extend(rems.clone());
    }

    result.into_iter().collect()
}

type AffectedPackage = (PackageKey, PackageValue);

#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct PackageKey {
    r#type: String,
    namespace: Option<String>,
    name: String,
    version: Option<String>,
    subpath: Option<String>,
    purl: String,
}

impl PackageKey {
    pub fn new(purl: &PackageUrl<'static>) -> Self {
        Self {
            r#type: purl.ty().to_string(),
            namespace: purl.namespace().map(ToString::to_string),
            name: purl.name().to_string(),
            version: purl.version().map(ToString::to_string),
            subpath: purl.subpath().map(ToString::to_string),
            purl: purl.to_string(),
        }
    }
}

#[derive(PartialEq)]
struct PackageValue {
    qualifiers: BTreeMap<String, BTreeSet<String>>,
    backtraces: Rc<BTreeMap<String, BTreeSet<Backtrace>>>,
    remediations: Vec<Remediation>,
}

#[derive(PartialEq, Properties)]
struct AffectedPackagesProperties {
    pub packages: Rc<Vec<AffectedPackage>>,
}

#[function_component(AffectedPackages)]
fn affected_packages(props: &AffectedPackagesProperties) -> Html {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Column {
        Type,
        Namespace,
        Name,
        Version,
        Path,
        Qualifiers,
    }

    impl TableEntryRenderer<Column> for (PackageKey, PackageValue) {
        fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
            match context.column {
                Column::Type => html!({ self.0.r#type.clone() }),
                Column::Namespace => html!({ for self.0.namespace.clone() }),
                Column::Name => html!({ self.0.name.clone() }),
                Column::Version => html!({ for self.0.version.clone() }),
                Column::Path => html!({ for self.0.subpath.clone() }),
                Column::Qualifiers => html!({ for self.1.qualifiers.iter().map(|(k,v)| html!(
                    { for v.iter().map(|v| {
                        html!(
                            <>
                                <Label compact=true label={format!("{k}: {v}")} /> {" "}
                            </>
                        )
                    })}
                ) ) }),
            }
            .into()
        }

        fn render_details(&self) -> Vec<Span> {
            let purls = self
                .1
                .backtraces
                .get(&self.0.purl)
                .iter()
                .flat_map(|p| *p)
                .map(|trace| trace.join(" » "))
                .collect::<Vec<_>>();

            let content = match purls.is_empty() {
                true => html!({ "Only direct dependencies" }),
                false => html!(
                    <List r#type={ListType::Basic}>
                        {
                            for self.1.backtraces.get(&self.0.purl).iter().flat_map(|p| *p).map(|trace| html_nested!(
                                <ListItem>
                                    { trace.join(" » ") }
                                </ListItem>
                            ))
                        }
                    </List>
                ),
            };

            let rems = html!(<>
                if !self.1.remediations.is_empty() {
                    <Title level={Level::H4}>{"Remediation"}</Title>
                    <List r#type={ListType::Basic}>
                        { for self.1.remediations.iter().map(|rem| {
                            html_nested! (
                                <ListItem> { rem.details.clone() } </ListItem>
                            )
                        })}
                    </List>
                }
            </>);

            let content = html!(
                <Grid>
                    <GridItem cols={[6]}>{content}</GridItem>
                    <GridItem cols={[6]}>{rems}</GridItem>
                </Grid>
            );

            vec![Span::max(content)]
        }
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Type} label="Type" />
            <TableColumn<Column> index={Column::Namespace} label="Namespace" />
            <TableColumn<Column> index={Column::Name} label="Name" />
            <TableColumn<Column> index={Column::Version} label="Version" />
            <TableColumn<Column> index={Column::Path} label="Path" />
            <TableColumn<Column> index={Column::Qualifiers} label="Qualifiers" />
        </TableHeader<Column>>
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(props.packages.clone()));

    html!(
        <>

            <Table<Column, UseTableData<Column, MemoizedTableModel<AffectedPackage>>>
                {header}
                {entries}
                {onexpand}
                mode={TableMode::CompactExpandable}
            />
        </>
    )
}
