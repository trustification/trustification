use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use spog_model::prelude::SbomReportVulnerability;
use spog_ui_components::{cvss::CvssScore, time::Date};
use spog_ui_navigation::{AppRoute, View};
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::str::FromStr;
use yew::prelude::*;
use yew_nested_router::components::Link;

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
                        if let Some(score) = self.vuln.score {
                            <CvssScore cvss={score} />
                        }
                    </>
                )
                .into(),
                Column::AffectedPackages => html!({ self.packages.len() }).into(),
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
                        <Link<AppRoute> target={AppRoute::Cve(View::Content {id: self.vuln.id.clone()})}>
                            {"All CVE details "} { Icon::ArrowRight }
                        </Link<AppRoute>>
                    )
                }
                Column::AffectedPackages => {
                    html!(<AffectedPackages packages={self.packages.clone()} />)
                }
                _ => html!(),
            };
            vec![Span::max(content)]
        }
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Id} label="Id" width={ColumnWidth::FitContent} expandable=true />
            <TableColumn<Column> index={Column::Description} label="Description" width={ColumnWidth::WidthMax} />
            <TableColumn<Column> index={Column::Cvss} label="CVSS" width={ColumnWidth::Percent(15)} />
            <TableColumn<Column> index={Column::AffectedPackages} label="Affected dependencies" width={ColumnWidth::FitContent} expandable=true />
            <TableColumn<Column> index={Column::Published} label="Published" width={ColumnWidth::FitContent} />
            <TableColumn<Column> index={Column::Updated} label="Updated" width={ColumnWidth::FitContent} />
        </TableHeader<Column>>
    );

    let entries = use_memo(props.sbom.clone(), |sbom| {
        sbom.details
            .iter()
            .map(|vuln| {
                let packages = Rc::new(build_packages(&vuln.affected_packages));
                Entry {
                    vuln: vuln.clone(),
                    packages,
                }
            })
            .collect::<Vec<_>>()
    });

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<Entry>>>
            {header}
            {entries}
            {onexpand}
            mode={TableMode::Expandable}
        />
    )
}

fn build_packages(packages: &BTreeSet<String>) -> Vec<(PackageKey, PackageValue)> {
    let mut result = BTreeMap::<PackageKey, PackageValue>::new();

    for purl in packages.iter().filter_map(|p| PackageUrl::from_str(p).ok()) {
        let key = PackageKey::new(&purl);
        let value = result.entry(key).or_default();
        for (k, v) in purl.qualifiers() {
            let qe = value.qualifiers.entry(k.to_string()).or_default();
            qe.insert(v.to_string());
        }
    }

    result.into_iter().collect()
}

type AffectedPackage = (PackageKey, PackageValue);

#[derive(PartialEq, Eq, Ord, PartialOrd)]
struct PackageKey {
    namespace: Option<String>,
    name: String,
    version: Option<String>,
}

impl PackageKey {
    pub fn new(purl: &PackageUrl<'static>) -> Self {
        Self {
            namespace: purl.namespace().map(ToString::to_string),
            name: purl.name().to_string(),
            version: purl.version().map(ToString::to_string),
        }
    }
}

#[derive(Default, PartialEq)]
struct PackageValue {
    qualifiers: BTreeMap<String, BTreeSet<String>>,
}

#[derive(PartialEq, Properties)]
struct AffectedPackagesProperties {
    pub packages: Rc<Vec<AffectedPackage>>,
}

#[function_component(AffectedPackages)]
fn affected_packages(props: &AffectedPackagesProperties) -> Html {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Column {
        Namespace,
        Name,
        Version,
        Qualifiers,
    }

    impl TableEntryRenderer<Column> for (PackageKey, PackageValue) {
        fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
            match context.column {
                Column::Namespace => html!({ for self.0.namespace.clone() }),
                Column::Name => html!({ self.0.name.clone() }),
                Column::Version => html!({ for self.0.version.clone() }),
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
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Namespace} label="Namespace" />
            <TableColumn<Column> index={Column::Name} label="Name" />
            <TableColumn<Column> index={Column::Version} label="Version" />
            <TableColumn<Column> index={Column::Qualifiers} label="Qualifiers" />
        </TableHeader<Column>>
    );

    let (entries, _onexpand) = use_table_data(MemoizedTableModel::new(props.packages.clone()));

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<AffectedPackage>>>
            {header}
            {entries}
            mode={TableMode::Compact}
        />
    )
}
