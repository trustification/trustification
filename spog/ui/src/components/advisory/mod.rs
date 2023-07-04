mod details;
mod search;

pub use search::*;

use crate::{backend::Endpoint, components::table_wrapper::TableWrapper, hooks::use_backend::use_backend};
use details::AdvisoryDetails;
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
use url::Url;
use yew::prelude::*;
use yew_more_hooks::prelude::UseAsyncState;

#[derive(PartialEq, Properties, Clone)]
pub struct AdvisoryEntry {
    summary: AdvisorySummary,
    url: Option<Url>,
}

#[derive(PartialEq, Properties)]
pub struct AdvisoryResultProperties {
    pub state: UseAsyncState<SearchResult<Rc<Vec<AdvisorySummary>>>, String>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Title,
    Revision,
    Download,
    Vulnerabilities,
}

impl TableEntryRenderer<Column> for AdvisoryEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(&self.summary.id).into(),
            Column::Title => html!(&self.summary.title).into(),
            Column::Revision => {
                let s = if let Ok(s) = self.summary.date.format(&time::format_description::well_known::Rfc3339) {
                    s.to_string()
                } else {
                    self.summary.date.to_string()
                };
                html!(s).into()
            }
            Column::Download => {
                if let Some(url) = &self.url {
                    html!(
                        <a href={url.as_str().to_string()}>
                            <Button icon={Icon::Download} variant={ButtonVariant::Plain} />
                        </a>
                    )
                    .into()
                } else {
                    html!().into()
                }
            }
            Column::Vulnerabilities => {
                let l = self.summary.cves.len();
                html!(if l == 0 {
                    {
                        "N/A"
                    }
                } else {
                    {
                        l.to_string()
                    }
                })
                .into()
            }
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!(<AdvisoryDetails advisory={Rc::new(self.summary.clone())} />);
        vec![Span::max(html)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(AdvisoryResult)]
pub fn vulnerability_result(props: &AdvisoryResultProperties) -> Html {
    let backend = use_backend();

    let data = match &props.state {
        UseAsyncState::Ready(Ok(val)) => {
            let data: Vec<AdvisoryEntry> = val
                .result
                .iter()
                .map(|summary| {
                    let url = backend.join(Endpoint::Api, &summary.href).ok();
                    AdvisoryEntry {
                        summary: summary.clone(),
                        url,
                    }
                })
                .collect();
            Some(data)
        }
        _ => None,
    };

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new(data.unwrap_or_default())));

    let header = vec![
        yew::props!(TableColumnProperties<Column> {
            index: Column::Id,
            label: "ID",
            width: ColumnWidth::Percent(15)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Title,
            label: "Title",
            width: ColumnWidth::Percent(45)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Revision,
            label: "Revision",
            width: ColumnWidth::Percent(15)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Download,
            label: "Download",
            width: ColumnWidth::Percent(5)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Vulnerabilities,
            label: "Vulnerabilities",
            width: ColumnWidth::Percent(15)
        }),
    ];

    html!(
        <TableWrapper<Column, UseTableData<Column, MemoizedTableModel<AdvisoryEntry>>>
            loading={&props.state.is_processing()}
            error={props.state.error().map(|val| val.clone())}
            empty={entries.is_empty()}
            {header}
        >
            <Table<Column, UseTableData<Column, MemoizedTableModel<AdvisoryEntry>>>
                {entries}
                mode={TableMode::Expandable}
                {onexpand}
            />
        </TableWrapper<Column, UseTableData<Column, MemoizedTableModel<AdvisoryEntry>>>>
    )
}
