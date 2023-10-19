use patternfly_yew::prelude::*;
use spog_model::prelude::SbomReportVulnerability;
use spog_ui_components::{cvss::CvssScore, time::Date};
use spog_ui_navigation::{AppRoute, View};
use std::rc::Rc;
use yew::prelude::*;
use yew_nested_router::components::Link;

#[derive(Clone, PartialEq, Properties)]
pub struct DetailsProps {
    pub sbom: Rc<spog_model::prelude::SbomReport>,
}

#[function_component(Details)]
pub fn details(props: &DetailsProps) -> Html {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Column {
        Id,
        Description,
        Cvss,
        Published,
        Updated,
    }

    impl TableEntryRenderer<Column> for SbomReportVulnerability {
        fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
            match context.column {
                Column::Id => html!(self.id.clone()).into(),
                Column::Description => html!({ for self.description.clone() }).into(),
                Column::Cvss => html!(
                    <>
                        if let Some(score) = self.score {
                            <CvssScore cvss={score} />
                        }
                    </>
                )
                .into(),
                Column::Published => Cell::from(html!(if let Some(timestamp) = self.published {
                    <Date {timestamp} />
                }))
                .text_modifier(TextModifier::NoWrap),
                Column::Updated => Cell::from(html!(if let Some(timestamp) = self.updated {
                    <Date {timestamp} />
                }))
                .text_modifier(TextModifier::NoWrap),
            }
        }

        fn render_column_details(&self, column: &Column) -> Vec<Span> {
            let content = match column {
                Column::Id => {
                    html!(
                        <Link<AppRoute> target={AppRoute::Cve(View::Content {id: self.id.clone()})}>
                            {"All CVE details "} { Icon::ArrowRight }
                        </Link<AppRoute>>
                    )
                }
                _ => html!(),
            };
            vec![Span::max(content)]
        }
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Id} label="Id" width={ColumnWidth::FitContent} expandable=true />
            <TableColumn<Column> index={Column::Description} label="Description" width={ColumnWidth::WidthMax} />
            <TableColumn<Column> index={Column::Cvss} label="CVSS" width={ColumnWidth::Percent(15)} />
            <TableColumn<Column> index={Column::Published} label="Published" width={ColumnWidth::FitContent} />
            <TableColumn<Column> index={Column::Updated} label="Updated" width={ColumnWidth::FitContent} />
        </TableHeader<Column>>
    );

    let entries = use_memo(props.sbom.clone(), |sbom| sbom.details.clone());

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<SbomReportVulnerability>>>
            {header}
            {entries}
            {onexpand}
            mode={TableMode::Expandable}
        />
    )
}
