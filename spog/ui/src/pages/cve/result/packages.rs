use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use spog_model::prelude::PackageRelatedToProductCve;
use spog_ui_navigation::AppRoute;
use std::{rc::Rc, str::FromStr};
use yew::prelude::*;
use yew_nested_router::components::Link;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Type,
    Namespace,
    Name,
    Version,
    Path,
    Qualifiers,
    DependencyType,
}

impl TableEntryRenderer<Column> for PackageRelatedToProductCve {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match PackageUrl::from_str(&self.purl) {
            Ok(package_url) => match context.column {
                Column::Type => html!({ package_url.ty() }),
                Column::Namespace => html!({ for package_url.namespace() }),
                Column::Name => html!(
                    <Link<AppRoute> target={AppRoute::Package {id: self.purl.clone()}}>
                        { package_url.name() }
                    </Link<AppRoute>>
                ),
                Column::Version => html!({ for package_url.version() }),
                Column::Path => html!({ for package_url.subpath() }),
                Column::Qualifiers => html!({ for package_url.qualifiers().iter().map(|(k,v)| html!(<Label label={format!("{k}={v}")} />)) }),
                Column::DependencyType => html!({ &self.r#type }),
            }
            .into(),
            Err(_) => match context.column {
                Column::Type => html!({ "N/A" }),
                Column::Namespace => html!({ "N/A" }),
                Column::Name => html!(
                    <Link<AppRoute> target={AppRoute::Package {id: self.purl.clone()}}>
                        { self.purl.clone() }
                    </Link<AppRoute>>
                ),
                Column::Version => html!({ "N/A" }),
                Column::Path => html!({ "N/A" }),
                Column::Qualifiers => html!({ "N/A" }),
                Column::DependencyType => html!({ &self.r#type }),
            }
            .into(),
        }
    }
}

#[derive(PartialEq, Properties)]
pub struct PackagesTableProperties {
    pub packages: Vec<PackageRelatedToProductCve>,
}

#[function_component(PackagesTable)]
pub fn related_products(props: &PackagesTableProperties) -> Html {
    let (entries, _) = use_table_data(MemoizedTableModel::new(Rc::new(props.packages.clone())));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Type" index={Column::Type} />
            <TableColumn<Column> label="Namespace" index={Column::Namespace} />
            <TableColumn<Column> label="Name" index={Column::Name} />
            <TableColumn<Column> label="Version" index={Column::Version} />
            <TableColumn<Column> label="Path" index={Column::Path} />
            <TableColumn<Column> label="Qualifiers" index={Column::Qualifiers} />
            <TableColumn<Column> label="Dependency tree position" index={Column::DependencyType} />
        </TableHeader<Column>>
    };

    html!(
        <div class="pf-v5-u-background-color-100">
            <Table<Column, UseTableData<Column, MemoizedTableModel<PackageRelatedToProductCve>>>
                mode={TableMode::Compact}
                {header}
                {entries}
            />
        </div>
    )
}
