mod report;
mod report_viewer;
mod search;

pub use report::*;
pub use report_viewer::*;
pub use search::*;

use crate::{download::Download, table_wrapper::TableWrapper};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use spog_ui_backend::{use_backend, Endpoint};
use spog_ui_common::{components::SafeHtml, utils::time::date};
use spog_ui_navigation::{AppRoute, View};
use spog_ui_utils::config::use_config;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use url::Url;
use yew::prelude::*;
use yew_more_hooks::hooks::UseAsyncState;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties)]
pub struct SbomResultProperties {
    pub state: UseAsyncState<SearchResult<Rc<Vec<SbomSummary>>>, String>,
    pub onsort: Callback<(String, Order)>,
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

#[derive(Clone, PartialEq)]
pub struct PackageEntry {
    url: Option<Url>,
    package: SbomSummary,
    link_advisories: bool,
    id: String,
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
                    target={AppRoute::Sbom(View::Content{id: self.package.id.clone()})}
                >{ self.package_name() }</Link<AppRoute>>
            )
            .into(),
            Column::Supplier => html!(&self.package.supplier).into(),
            Column::Created => date(self.package.created).into(),
            Column::Download => html!(
                if let Some(url) = &self.url {
                    <Download href={url.clone()} r#type="sbom"/>
                }
            )
            .into(),
            Column::Dependencies => html!(&self.package.dependencies).into(),
            Column::Advisories => match self.package.advisories_query() {
                Some(query) if self.link_advisories => html!(
                    <Link<AppRoute>
                        target={AppRoute::Advisory(View::Search { query })}
                    >
                        { for self.package.advisories }
                    </Link<AppRoute>>
                ),
                Some(_) => html!({ for self.package.advisories }),
                None => html!(),
            }
            .into(),
            Column::Version => html!(&self.package.version).into(),
        }
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!(<PackageDetails package={Rc::new(self.clone())} />);
        vec![Span::max(html)]
    }
}

#[function_component(SbomResult)]
pub fn sbom_result(props: &SbomResultProperties) -> Html {
    let backend = use_backend();
    let config = use_config();
    let link_advisories = config.features.dedicated_search;

    let data = use_state_eq(|| None);

    if let UseAsyncState::Ready(Ok(val)) = &props.state {
        let response: Vec<PackageEntry> = val
            .result
            .iter()
            .map(|pkg| {
                let url = backend.join(Endpoint::Api, &pkg.href).ok();
                PackageEntry {
                    package: pkg.clone(),
                    url,
                    link_advisories,
                    id: pkg.id.clone(),
                }
            })
            .collect();
        data.set(Some(response));
    }

    let sortby: UseStateHandle<Option<TableHeaderSortBy<Column>>> = use_state_eq(|| None);
    let onsort = use_callback(
        (sortby.clone(), props.onsort.clone()),
        |val: TableHeaderSortBy<Column>, (sortby, onsort)| {
            sortby.set(Some(val));
            if val.index == Column::Created {
                onsort.emit(("created".to_string(), val.order));
            };
        },
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new((*data).clone().unwrap_or_default())));

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
            width: ColumnWidth::Percent(10),
            sortby: *sortby,
            onsort: onsort.clone()
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Dependencies,
            label: "Dependencies",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Advisories,
            label: "Product advisories",
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
                // For now, we skip showing details, as we don't have good data.
                // mode={TableMode::Expandable}
                mode={TableMode::Default}
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
