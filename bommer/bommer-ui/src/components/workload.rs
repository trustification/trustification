use std::rc::Rc;

use bommer_api::data::{Image, ImageRef, SbomState};
use itertools::Itertools;
use patternfly_yew::next::{
    use_table_data, Cell, CellContext, ColumnWidth, MemoizedTableModel, Table, TableColumn, TableEntryRenderer,
    TableHeader, UseTableData,
};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct WorkloadTableProperties {
    pub workload: Rc<crate::backend::Workload>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Column {
    Id,
    NumPods,
    State,
}

#[derive(PartialEq)]
pub struct WorkloadEntry {
    id: ImageRef,
    state: Image,
}

impl TableEntryRenderer<Column> for WorkloadEntry {
    fn render_cell(&self, context: &CellContext<Column>) -> Cell {
        match context.column {
            Column::Id => html!(self.id.to_string()).into(),
            Column::NumPods => html!(self.state.pods.len()).into(),
            Column::State => match &self.state.sbom {
                SbomState::Scheduled => html!("Retrieving…").into(),
                SbomState::Missing => html!("Missing").into(),
                SbomState::Err(err) => Cell::new(html!(
                    <Tooltip text={err.to_string()}>
                        { format!("Failed ({err})") }
                    </Tooltip>
                ))
                .text_modifier(TextModifier::Truncate),
                SbomState::Found(_) => html!("Found").into(),
            },
        }
    }

    fn render_details(&self) -> Vec<Span> {
        vec![Span::max(html!(
            <ul>
                { for self.state.pods.iter().sorted_unstable().map(| pod|{
                    html!(<li> { &pod.namespace }  { " / " } { &pod.name} </li> )
                })}
            </ul>
        ))]
    }
}

#[function_component(WorkloadTable)]
pub fn workload_table(props: &WorkloadTableProperties) -> Html {
    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Id} label="Image" width={ColumnWidth::Percent(80)} />
            <TableColumn<Column> index={Column::NumPods} label="Pods" width={ColumnWidth::Percent(5)}   />
            <TableColumn<Column> index={Column::State} label="SBOM" width={ColumnWidth::Percent(10)}  />
        </TableHeader<Column>>
    );

    let entries = use_memo(
        |workload| {
            let mut entries = Vec::with_capacity(workload.len());
            for (k, v) in workload.0.iter().sorted_unstable_by_key(|(k, _)| *k) {
                entries.push(WorkloadEntry {
                    id: k.clone(),
                    state: v.clone(),
                })
            }
            entries
        },
        props.workload.clone(),
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<WorkloadEntry>>>
            {header}
            grid={TableGridMode::Medium}
            {entries} {onexpand}
            mode={TableMode::CompactExpandable}
        />
    )
}
