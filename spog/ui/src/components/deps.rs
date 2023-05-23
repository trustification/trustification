use crate::{backend::data, pages::AppRoute};
use itertools::Itertools;
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use std::cmp::Ordering;
use std::str::FromStr;
use yew::prelude::*;
use yew_nested_router::components::Link;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct PackageRefsProperties {
    #[prop_or_default]
    pub refs: Vec<data::PackageRef>,
}

struct PackageRef {
    label: String,
    purl: PackageUrl<'static>,
    pkg: data::PackageRef,
}

impl PartialEq for PackageRef {
    fn eq(&self, other: &Self) -> bool {
        self.pkg.purl == other.pkg.purl
    }
}

impl Eq for PackageRef {}

impl PartialOrd for PackageRef {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PackageRef {
    fn cmp(&self, other: &Self) -> Ordering {
        let a = &self.purl;
        let b = &other.purl;

        a.ty()
            .cmp(&b.ty())
            .then_with(|| a.namespace().cmp(&b.namespace()))
            .then_with(|| a.name().cmp(b.name()))
            .then_with(|| a.version().cmp(&b.version()))
    }
}

impl TableEntryRenderer for PackageRef {
    fn render_cell(&self, context: &CellContext) -> Cell {
        match context.column {
            0 => html!(
                <>
                    <Link<AppRoute> target={AppRoute::Package {package: self.pkg.purl.clone()}}>{&self.label}</Link<AppRoute>>
                </>
            ),
            1 => self.purl.version().map(Html::from).unwrap_or_default(),
            2 => html!(self.purl.ty()),
            3 => html!(
                { for self.purl.qualifiers().iter().sorted_by_key(|(k,_)|k.clone()).map(|(k,v)|
                    html!(<>
                        {" "} <Label compact=true label={format!("{k}={v}")} />
                    </>))
                }
            ),
            _ => html!(),
        }
            .into()
    }
}

#[function_component(PackageReferences)]
pub fn package_refs(props: &PackageRefsProperties) -> Html {
    let mut refs = Vec::with_capacity(props.refs.len());
    for pkg in &props.refs {
        let purl = match PackageUrl::from_str(&pkg.purl) {
            Ok(purl) => purl,
            Err(_) => continue,
        };
        let label = match purl.namespace() {
            Some(namespace) => format!("{namespace} : {name}", name = purl.name()),
            None => purl.name().to_string(),
        };
        refs.push(PackageRef {
            label,
            purl,
            pkg: pkg.clone(),
        });
    }

    refs.sort_unstable();

    let header = html_nested!(
        <TableHeader>
            <TableColumn label="Name" />
            <TableColumn label="Version"/>
            <TableColumn/>
            <TableColumn/>
        </TableHeader>
    );

    let entries = SharedTableModel::new(refs);

    html!(
        <Table<SharedTableModel<PackageRef>>
            mode={TableMode::CompactNoBorders}
            {header} {entries}
        />
    )
}
