mod search;

use crate::table_wrapper::TableWrapper;
use patternfly_yew::prelude::*;
pub use search::*;
use serde_json::from_str;
use spog_model::package_Info::{PackageInfo, V11yRef};
use spog_model::search::PackageInfoSummary;
use spog_ui_navigation::{AppRoute, View};
use std::rc::Rc;
use trustification_api::search::SearchResult;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties, Clone)]
pub struct PackagesEntry {
    package: PackageInfo,
}

#[derive(PartialEq, Properties)]
pub struct PackagesResultProperties {
    pub state: UseAsyncState<SearchResult<Rc<Vec<PackageInfoSummary>>>, String>,
    pub onsort: Callback<(String, Order)>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Name,
    Version,
    PackageType,
    Description,
    Supplier,
    Vulnerabilities,
}

impl TableEntryRenderer<Column> for PackagesEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => html!(
                <Link<AppRoute>
                    target={AppRoute::Package{id: self.package.purl.clone().unwrap_or_default()}}
                >{ self.package.name.clone().unwrap_or_default() }</Link<AppRoute>>
            ),
            Column::Version => html!( <>
                {
                    self.package.version.clone().unwrap_or_default()
                }
            </>),
            Column::PackageType => html!( <>
                {
                    self.package.package_type.clone().unwrap_or_default()
                }
                </>),
            Column::Description => html!( <>
                {
                    self.package.description.clone().unwrap_or_default()
                }
                </>),
            Column::Supplier => html!( <>
                {
                    self.package.supplier.clone().unwrap_or_default()
                }
                </>),
            Column::Vulnerabilities => html!( <>
                {
                    self.package.package_type.clone().unwrap_or_default()
                }
                </>),
        }
        .into()
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!();
        vec![Span::max(html)]
    }
}

fn get_package_definitions(pkg: &PackageInfoSummary) -> PackagesEntry {
    let pkg = PackageInfo {
        name: pkg.name.clone().into(),
        package_type: pkg.packageType.clone().into(),
        version: pkg.version.clone().into(),
        purl: pkg.purl.clone(),
        href: pkg.href.clone().into(),
        sbom: pkg.sbom.clone().into(),
        supplier: pkg.supplier.clone().into(),
        vulnerabilities: pkg.vulnerabilities.clone().into(),
        description: pkg.description.clone().into(),
    };
    PackagesEntry { package: pkg }
}

#[function_component(PackagesResult)]
pub fn package_result(props: &PackagesResultProperties) -> Html {
    let data = match &props.state {
        UseAsyncState::Ready(Ok(val)) => {
            let data: Vec<_> = val.result.iter().map(|pkg| get_package_definitions(pkg)).collect();
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
                Column::Name => {
                    onsort.emit(("name".to_string(), val.order));
                }
                Column::Version => {
                    onsort.emit(("version".to_string(), val.order));
                }
                Column::PackageType => {
                    onsort.emit(("package_type".to_string(), val.order));
                }
                _ => {}
            }
        },
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new(data.unwrap_or_default())));

    let header = vec![
        yew::props!(TableColumnProperties<Column> {
            index: Column::Name,
            label: "Name",
            width: ColumnWidth::Percent(10),
            sortby: *sortby,
            onsort: onsort.clone()
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Version,
            label: "Version",
            width: ColumnWidth::Percent(10),
            sortby: *sortby,
            onsort: onsort.clone()
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::PackageType,
            label: "Type",
            width: ColumnWidth::Percent(10),
            // text_modifier: Some(TextModifier::Wrap),
            sortby: *sortby,
            onsort: onsort.clone()
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Description,
            label: "Description",
            width: ColumnWidth::Percent(30),
            // text_modifier: Some(TextModifier::Wrap),
            sortby: *sortby,
            onsort: onsort.clone()
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Vulnerabilities,
            label: "Vulnerabilities",
            width: ColumnWidth::Percent(20),
        }),
    ];

    html!(
        <TableWrapper<Column, UseTableData<Column, MemoizedTableModel<PackagesEntry>>>
            loading={&props.state.is_processing()}
            error={props.state.error().cloned()}
            empty={entries.is_empty()}
            {header}
        >
            <Table<Column, UseTableData<Column, MemoizedTableModel<PackagesEntry>>>
                {entries}
                mode={TableMode::Default}
                {onexpand}
            />
        </TableWrapper<Column, UseTableData<Column, MemoizedTableModel<PackagesEntry>>>>
    )
}
