use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use spog_ui_navigation::AppRoute;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::str::FromStr;
use yew::prelude::*;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties)]
pub struct AffectedPackagesProperties {
    pub packages: Rc<Vec<AffectedPackage>>,
}

#[function_component(AffectedPackages)]
pub fn affected_packages(props: &AffectedPackagesProperties) -> Html {
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
                Column::Name => html!(
                    <Link<AppRoute> target={AppRoute::Package {id: self.0.purl.clone()}}>
                        { self.0.name.clone() }
                    </Link<AppRoute>>
                ),
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

pub fn build_packages<'a>(
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

pub type AffectedPackage = (PackageKey, PackageValue);

#[derive(PartialEq, Eq, Ord, PartialOrd)]
pub struct PackageKey {
    pub r#type: String,
    pub namespace: Option<String>,
    pub name: String,
    pub version: Option<String>,
    pub subpath: Option<String>,
    pub purl: String,
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
pub struct PackageValue {
    pub qualifiers: BTreeMap<String, BTreeSet<String>>,
    pub backtraces: Rc<BTreeMap<String, BTreeSet<Backtrace>>>,
    pub remediations: Vec<Remediation>,
}
