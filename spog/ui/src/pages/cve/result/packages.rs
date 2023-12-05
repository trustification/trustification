use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use spog_model::prelude::PackageRelatedToProductCve;
use spog_ui_navigation::AppRoute;
use std::{rc::Rc, str::FromStr};
use yew::prelude::*;
use yew_nested_router::components::Link;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Name,
    Version,
    Qualifiers,
    Type,
}

impl TableEntryRenderer<Column> for PackageRelatedToProductCve {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match PackageUrl::from_str(&self.purl) {
            Ok(purl) => match context.column {
                Column::Name => html!(
                    <Link<AppRoute> target={AppRoute::Package {id: self.purl.clone()}}>
                        { purl.name() }
                    </Link<AppRoute>>
                ),
                Column::Qualifiers => html!({ for purl.qualifiers().iter().map(|(k,v)| html!(
                    html!(
                        <>
                            <Label compact=true label={format!("{k}: {v}")} /> {" "}
                        </>
                    )
                ) ) }),
                Column::Version => html!({ for purl.version() }),
                Column::Type => html!({ &self.r#type }),
            }
            .into(),
            Err(_) => match context.column {
                Column::Name => html!(
                    <Link<AppRoute> target={AppRoute::Package {id: self.purl.clone()}}>
                        { self.purl.clone() }
                    </Link<AppRoute>>
                ),
                Column::Version => html!({ "N/A" }),
                Column::Qualifiers => html!({ "N/A" }),
                Column::Type => html!({ &self.r#type }),
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
            <TableColumn<Column> label="Package name" index={Column::Name} />
            <TableColumn<Column> label="Version" index={Column::Version} />
            <TableColumn<Column> width={ColumnWidth::Percent(50)} index={Column::Qualifiers} label="Qualifiers" />
            <TableColumn<Column> label="Dependency tree position" index={Column::Type} />
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
