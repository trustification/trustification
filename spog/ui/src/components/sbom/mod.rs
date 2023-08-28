mod search;

pub use search::*;

use std::rc::Rc;

use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use url::Url;
use yew::prelude::*;
use yew_more_hooks::hooks::UseAsyncState;
use yew_nested_router::components::Link;

use crate::{
    backend::Endpoint,
    components::{common::SafeHtml, download::Download, table_wrapper::TableWrapper},
    hooks::*,
    pages::{AppRoute, View},
    utils::time::date,
};

#[derive(PartialEq, Properties)]
pub struct PackageResultProperties {
    pub state: UseAsyncState<SearchResult<Rc<Vec<PackageSummary>>>, String>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Name,
    Supplier,
    Created,
    Download,
    Dependencies,
    Advisories,
    Version,
}

#[derive(Clone)]
pub struct PackageEntry {
    url: Option<Url>,
    package: PackageSummary,
}

impl PackageEntry {
    fn package_name(&self) -> Html {
        if self.package.name.is_empty() {
            html!(<i>{ &self.package.id }</i>)
        } else {
            (&self.package.name).into()
        }
    }
}

impl TableEntryRenderer<Column> for PackageEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => html!(
                <Link<AppRoute>
                    target={AppRoute::Package(View::Content{id: self.package.id.clone()})}
                >{ self.package_name() }</Link<AppRoute>>
            )
            .into(),
            Column::Supplier => html!(&self.package.supplier).into(),
            Column::Created => date(self.package.created).into(),
            Column::Download => html!(
                if let Some(url) = &self.url {
                    <Download href={url.clone()} />
                }
            )
            .into(),
            Column::Dependencies => html!(&self.package.dependencies.len()).into(),
            Column::Advisories => {
                let q = self.package.advisories_query();
                html!(<Link<AppRoute>
                          target={AppRoute::Advisory(View::Search{query: q})}
                            >
                        { self.package.advisories.len() }
                    </Link<AppRoute>>
                )
                .into()
            }
            Column::Version => html!(&self.package.version).into(),
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!(<PackageDetails package={Rc::new(self.clone())} />);
        vec![Span::max(html)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(PackageResult)]
pub fn sbom_result(props: &PackageResultProperties) -> Html {
    let backend = use_backend();
    let data = match &props.state {
        UseAsyncState::Ready(Ok(val)) => {
            let data: Vec<PackageEntry> = val
                .result
                .iter()
                .map(|pkg| {
                    let url = backend.join(Endpoint::Api, &pkg.href).ok();
                    PackageEntry {
                        package: pkg.clone(),
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
            index: Column::Name,
            label: "Name",
            width: ColumnWidth::Percent(15)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Version,
            label: "Version",
            width: ColumnWidth::Percent(20)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Supplier,
            label: "Supplier",
            width: ColumnWidth::Percent(20)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Created,
            label: "Created on",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Dependencies,
            label: "Dependencies",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Advisories,
            label: "Advisories",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Download,
            label: "Download",
            width: ColumnWidth::FitContent
        }),
    ];

    html!(
        <TableWrapper<Column, UseTableData<Column, MemoizedTableModel<PackageEntry>>>
            loading={&props.state.is_processing()}
            error={props.state.error().cloned()}
            empty={entries.is_empty()}
            header={header}
        >
            <Table<Column, UseTableData<Column, MemoizedTableModel<PackageEntry>>>
                mode={TableMode::Expandable}
                {entries}
                {onexpand}
            />
        </TableWrapper<Column, UseTableData<Column, MemoizedTableModel<PackageEntry>>>>
    )
}

#[derive(Clone, Properties)]
pub struct PackageDetailsProps {
    pub package: Rc<PackageEntry>,
}

impl PartialEq for PackageDetailsProps {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.package, &other.package)
    }
}

#[function_component(PackageDetails)]
pub fn package_details(props: &PackageDetailsProps) -> Html {
    let mut snippet = props.package.package.snippet.clone();

    if snippet.is_empty() {
        snippet = "No description available".to_string();
    }

    html!(
        <Panel>
            <PanelMain>
                <PanelMainBody>
                    <SafeHtml html={snippet} />
                </PanelMainBody>
            </PanelMain>
        </Panel>
    )
}
