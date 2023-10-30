use crate::pages::search::PaginationWrapped;
use patternfly_yew::prelude::*;
use spog_model::{prelude::V11yRef, search::PackageInfoSummary};
use std::rc::Rc;
use yew::prelude::*;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Description,
    CVSS,
    DiscoveredOn,
    ReleasedOn,
    CWE,
}

impl TableEntryRenderer<Column> for V11yRef {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!({ &self.cve }),
            Column::Description => html!({ "Description" }),
            Column::CVSS => html!({ "CVSS" }),
            Column::DiscoveredOn => html!({ "DiscoveredOn" }),
            Column::ReleasedOn => html!({ "ReleasedOn" }),
            Column::CWE => html!({ "CWE" }),
        }
        .into()
    }
}

#[derive(PartialEq, Properties)]
pub struct VulnerabilitiesProperties {
    pub package: Rc<PackageInfoSummary>,
}

#[function_component(Vulnerabilities)]
pub fn vulnerabilities(props: &VulnerabilitiesProperties) -> Html {
    let total = props.package.vulnerabilities.len();
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new(props.package.vulnerabilities.clone())));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="ID" index={Column::Id} />
            <TableColumn<Column> label="Description" index={Column::Description} />
            <TableColumn<Column> label="CVSS" index={Column::CVSS} />
            <TableColumn<Column> label="Discovered on" index={Column::DiscoveredOn} />
            <TableColumn<Column> label="Released on" index={Column::ReleasedOn} />
            <TableColumn<Column> label="CWE" index={Column::CWE} />
        </TableHeader<Column>>
    };

    let pagination = use_pagination(Some(total), || PaginationControl { page: 1, per_page: 10 });

    match props.package.vulnerabilities.is_empty() {
        true => html!(
            <Panel>
                <PanelMain>
                    <Bullseye>
                        <EmptyState
                            title="No related CVEs"
                            icon={Icon::Search}
                        >
                            { "No related CVEs have been found." }
                        </EmptyState>
                    </Bullseye>
                </PanelMain>
            </Panel>
        ),
        false => html!(
            <div class="pf-v5-u-background-color-100">
                <PaginationWrapped pagination={pagination} total={10}>
                    <Table<Column, UseTableData<Column, MemoizedTableModel<V11yRef>>>
                        {header}
                        {entries}
                    />
                </PaginationWrapped>
            </div>
        ),
    }
}
