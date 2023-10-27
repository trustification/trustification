mod search;

pub use search::*;

use crate::cvss::CvssScore;
use crate::table_wrapper::TableWrapper;
use patternfly_yew::prelude::*;
use spog_model::cve::CveSearchDocument;
use spog_ui_common::{utils::cvss::Cvss, utils::time::date, utils::OrNone};
use spog_ui_navigation::{AppRoute, View};
use std::rc::Rc;
use trustification_api::search::SearchResult;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties, Clone)]
pub struct CveEntry {
    cve: CveSearchDocument,
}

#[derive(PartialEq, Properties)]
pub struct CveResultProperties {
    pub state: UseAsyncState<SearchResult<Rc<Vec<CveSearchDocument>>>, String>,
    pub onsort: Callback<(String, Order)>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Description,
    Severity,
    DatePublished,
    Related,
}

impl TableEntryRenderer<Column> for CveEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(
                <Link<AppRoute>
                    target={AppRoute::Cve(View::Content{id: self.cve.id.clone()})}
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
                    if let Some(score)= &self.cve.cvss3x_score {
                        <CvssScore cvss={Cvss{score: (*score) as _}} />
                    }
                </>
            ),
            Column::DatePublished => html!({ OrNone(self.cve.date_published).map(date) }),
            Column::Related => {
                html!({ self.cve.related_advisories })
            }
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
            match &val.index {
                Column::Severity => {
                    onsort.emit(("score".to_string(), val.order));
                }
                Column::DatePublished => {
                    onsort.emit(("datePublished".to_string(), val.order));
                }
                _ => {}
            }
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
        yew::props!(TableColumnProperties<Column> {
            index: Column::DatePublished,
            label: "Date published",
            width: ColumnWidth::Percent(20),
            text_modifier: Some(TextModifier::Wrap),
            sortby: *sortby,
            onsort: onsort.clone()
        }),
        yew::props!(TableColumnProperties<Column> {
             index: Column::Related,
             label: "Related documents",
             width: ColumnWidth::Percent(10),
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
                mode={TableMode::Default}
                {onexpand}
            />
        </TableWrapper<Column, UseTableData<Column, MemoizedTableModel<CveEntry>>>>
    )
}
