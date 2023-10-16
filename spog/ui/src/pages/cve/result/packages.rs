use patternfly_yew::prelude::*;
use spog_model::prelude::{CveDetails, PackageRelatedToProductCve, ProductCveStatus};
use std::rc::Rc;
use yew::prelude::*;

use crate::pages::search::PaginationWrapped;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Name,
    Type,
}

impl TableEntryRenderer<Column> for PackageRelatedToProductCve {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => html!({ &self.purl }),
            Column::Type => html!({ &self.r#type }),
        }
        .into()
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
