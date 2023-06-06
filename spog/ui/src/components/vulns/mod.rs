mod details;

use csaf::Csaf;
use details::CsafDetails;
use patternfly_yew::{
    next::{
        use_table_data, Cell, CellContext, ColumnWidth, MemoizedTableModel, Table, TableColumn, TableEntryRenderer,
        TableHeader, UseTableData,
    },
    prelude::*,
};
use spog_model::prelude::*;
use std::rc::Rc;
use yew::prelude::*;

#[derive(Debug, Properties)]
pub struct VulnerabilityResultProperties {
    pub result: SearchResult<Rc<Vec<csaf::Csaf>>>,
}

impl PartialEq for VulnerabilityResultProperties {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.result, &other.result)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Title,
    Revision,
    Products,
    Vulnerabilities,
}

impl TableEntryRenderer<Column> for Csaf {
    fn render_cell(&self, context: &CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(&self.document.tracking.id).into(),
            Column::Title => html!(&self.document.title).into(),
            Column::Revision => html!(&self.document.tracking.current_release_date.to_rfc3339()).into(),
            Column::Products => html!().into(),
            Column::Vulnerabilities => self
                .vulnerabilities
                .as_ref()
                .map(|v| html!(v.len().to_string()))
                .unwrap_or_else(|| html!(<i>{"N/A"}</i>))
                .into(),
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!(<CsafDetails csaf={Rc::new(self.clone())} />);
        vec![Span::max(html)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(VulnerabilityResult)]
pub fn vulnerability_result(props: &VulnerabilityResultProperties) -> Html {
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(props.result.result.clone()));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="ID" index={Column::Id} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Title" index={Column::Title} width={ColumnWidth::Percent(55)}/>
            <TableColumn<Column> label="Revision" index={Column::Revision} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Products" index={Column::Products} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Vulnerabilities" index={Column::Vulnerabilities} width={ColumnWidth::Percent(10)}/>
        </TableHeader<Column>>
    };

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<Csaf>>>
            mode={TableMode::CompactExpandable}
            {header}
            {entries}
            {onexpand}
        />
    )
}
