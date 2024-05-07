mod cve;
mod packages;

use packages::*;
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use spog_ui_common::use_apply_pagination;
use spog_ui_components::{cvss::CvssScore, pagination::PaginationWrapped, time::Date};
use std::cmp::Ordering;
use std::rc::Rc;
use yew::prelude::*;

#[derive(Clone, PartialEq, Properties)]
pub struct DetailsProps {
    pub sbom: Rc<SbomReport>,
}

#[function_component(Details)]
pub fn details(props: &DetailsProps) -> Html {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Column {
        Id,
        Description,
        Cvss,
        AffectedPackages,
        Published,
        Updated,
    }

    #[derive(Clone, PartialEq)]
    struct Entry {
        vuln: SbomReportVulnerability,
        packages: Rc<Vec<AffectedPackage>>,
    }

    impl TableEntryRenderer<Column> for Entry {
        fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
            match context.column {
                Column::Id => Cell::new(html!(self.vuln.id.clone())).text_modifier(TextModifier::NoWrap),
                Column::Description => html!({ for self.vuln.description.clone() }).into(),
                Column::Cvss => html!(
                    <>
                        if let Some(score) = self.vuln.score("mitre") {
                            <CvssScore cvss={score} />
                        }
                    </>
                )
                .into(),
                Column::AffectedPackages => {
                    let rems: usize = self.packages.iter().map(|p| p.1.remediations.len()).sum();
                    html!(
                        <>
                            { self.packages.len() }
                            if rems > 0 {
                                {" / "}
                                { rems }
                            }
                        </>
                    )
                    .into()
                }
                Column::Published => Cell::from(html!(if let Some(timestamp) = self.vuln.published {
                    <Date {timestamp} />
                }))
                .text_modifier(TextModifier::NoWrap),
                Column::Updated => Cell::from(html!(if let Some(timestamp) = self.vuln.updated {
                    <Date {timestamp} />
                }))
                .text_modifier(TextModifier::NoWrap),
            }
        }

        fn render_column_details(&self, column: &Column) -> Vec<Span> {
            let content = match column {
                Column::Id => {
                    html!(
                        <cve::Details id={self.vuln.id.clone()} />
                    )
                }
                Column::AffectedPackages => {
                    html!(<AffectedPackages
                            packages={self.packages.clone()}
                        />)
                }
                _ => html!(),
            };
            vec![Span::max(content)]
        }
    }

    let sort_by = use_state_eq(|| TableHeaderSortBy::ascending(Column::Id));
    let onsort = use_callback(sort_by.clone(), |value, sort_by| sort_by.set(value));

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Id} label="Id" width={ColumnWidth::FitContent} expandable=true sortby={*sort_by} onsort={onsort.clone()} />
            <TableColumn<Column> index={Column::Description} label="Description" width={ColumnWidth::WidthMax} />
            <TableColumn<Column> index={Column::Cvss} label="CVSS" width={ColumnWidth::Percent(15)} sortby={*sort_by} onsort={onsort.clone()} />
            <TableColumn<Column> index={Column::AffectedPackages} label="Affected dependencies" width={ColumnWidth::FitContent} expandable=true sortby={*sort_by} onsort={onsort.clone()} />
            <TableColumn<Column> index={Column::Published} label="Published" width={ColumnWidth::FitContent} sortby={*sort_by} onsort={onsort.clone()} />
            <TableColumn<Column> index={Column::Updated} label="Updated" width={ColumnWidth::FitContent} sortby={*sort_by} onsort={onsort.clone()} />
        </TableHeader<Column>>
    );

    let entries = use_memo((props.sbom.clone(), *sort_by), |(sbom, sort_by)| {
        let backtraces = Rc::new(sbom.backtraces.clone());
        let mut result = sbom
            .details
            .iter()
            .map(|vuln| {
                let packages = Rc::new(build_packages(&vuln.affected_packages, backtraces.clone()));
                Entry {
                    vuln: vuln.clone(),
                    packages,
                }
            })
            .collect::<Vec<_>>();

        result.sort_by(|a, b| {
            let result = match sort_by.index {
                Column::Cvss => a
                    .vuln
                    .score("mitre")
                    .partial_cmp(&b.vuln.score("mitre"))
                    .unwrap_or(Ordering::Equal),
                Column::AffectedPackages => a.vuln.affected_packages.len().cmp(&b.vuln.affected_packages.len()),
                Column::Published => a.vuln.published.cmp(&b.vuln.published),
                Column::Updated => a.vuln.updated.cmp(&b.vuln.updated),
                _ => a.vuln.id.cmp(&b.vuln.id),
            };

            match sort_by.order {
                Order::Ascending => result,
                Order::Descending => result.reverse(),
            }
        });

        result
    });

    let total = entries.len();
    let pagination = use_pagination(Some(total), Default::default);

    // page from the filtered entries
    let entries = use_apply_pagination(entries, pagination.control);

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    match total {
        0 => html!(),
        _ => html!(
            <div class="pf-v5-u-background-color-100">
                <PaginationWrapped {pagination} {total}>
                    <Table<Column, UseTableData<Column, MemoizedTableModel<Entry>>>
                        {header}
                        {entries}
                        {onexpand}
                        mode={TableMode::Expandable}
                    />
                </PaginationWrapped>
            </div>
        ),
    }
}
