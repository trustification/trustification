mod search;

pub use search::*;

use crate::cvss::CvssScore;
use crate::table_wrapper::TableWrapper;
use patternfly_yew::prelude::*;
use spog_ui_common::utils::cvss::Cvss;
use spog_ui_navigation::AppRoute;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use v11y_model::search::SearchDocument;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties, Clone)]
pub struct CveEntry {
    cve: SearchDocument,
}

#[derive(PartialEq, Properties)]
pub struct CveResultProperties {
    pub state: UseAsyncState<SearchResult<Rc<Vec<SearchDocument>>>, String>,
    pub onsort: Callback<(String, bool)>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Description,
    Severity,
}

impl TableEntryRenderer<Column> for CveEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(
                <Link<AppRoute>
                    target={AppRoute::Cve{id: self.cve.id.clone()}}
                >{ self.cve.id.clone() }</Link<AppRoute>>
            ),
            Column::Description => html!( <>
                if let Some(title) = &self.cve.title {
                    { title }
                } else {
                    { for self.cve.descriptions.iter() }
                }
            </>),
            Column::Severity => html!(
                <>
                    if let Some(score)= &self.cve.cvss31_score {
                        <CvssScore cvss={Cvss{score: (*score) as _}} />
                    } else if let Some(score) = &self.cve.cvss30_score {
                        <CvssScore cvss={Cvss{score: (*score) as _}} />
                    }
                </>
            ),
        }
        .into()
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }

    fn render_details(&self) -> Vec<Span> {
        //let html = html!( <CveDetails advisory={Rc::new(self.summary.clone())} />);
        let html = html!();
        vec![Span::max(html)]
    }
}

#[function_component(CveResult)]
pub fn cve_result(props: &CveResultProperties) -> Html {
    let data = match &props.state {
        UseAsyncState::Ready(Ok(val)) => {
            let data: Vec<_> = val
                .result
                .iter()
                .map(|vulnerability| CveEntry {
                    cve: vulnerability.clone(),
                })
                .collect();
            Some(data)
        }
        _ => None,
    };

    let sortby: UseStateHandle<Option<TableHeaderSortBy<Column>>> = use_state_eq(|| None);
    let onsort = use_callback(
        (sortby.clone(), props.onsort.clone()),
        |val: TableHeaderSortBy<Column>, (sortby, onsort)| {
            sortby.set(Some(val));
            if val.index == Column::Severity {
                onsort.emit(("severity".to_string(), val.asc));
            };
        },
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new(data.unwrap_or_default())));

    let header = vec![
        yew::props!(TableColumnProperties<Column> {
            index: Column::Id,
            label: "ID",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Description,
            label: "Description",
            width: ColumnWidth::Percent(50)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Severity,
            label: "CVSS",
            width: ColumnWidth::Percent(10),
            text_modifier: Some(TextModifier::Wrap),
            sortby: *sortby,
            onsort: onsort.clone()
        }),
    ];

    html!(
        <TableWrapper<Column, UseTableData<Column, MemoizedTableModel<CveEntry>>>
            loading={&props.state.is_processing()}
            error={props.state.error().cloned()}
            empty={entries.is_empty()}
            {header}
        >
            <Table<Column, UseTableData<Column, MemoizedTableModel<CveEntry>>>
                {entries}
                mode={TableMode::Expandable}
                {onexpand}
            />
        </TableWrapper<Column, UseTableData<Column, MemoizedTableModel<CveEntry>>>>
    )
}
