use patternfly_yew::prelude::*;
use spog_model::prelude::SbomReportVulnerability;
use spog_ui_components::{cvss::CvssScore, time::Date};
use std::rc::Rc;
use yew::prelude::*;

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
                Column::Id => html!(self.id.clone()),
                Column::Description => html!(self.description.clone()),
                Column::Cvss => html!(
                    <>
                        if let Some(score) = self.score {
                            <CvssScore cvss={score} />
                        }
                    </>
                ),
                Column::Published => html!(if let Some(timestamp) = self.published {
                    <Date {timestamp} />
                }),
                Column::Updated => html!(if let Some(timestamp) = self.updated {
                    <Date {timestamp} />
                }),
            }
            .into()
        }
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Id} label="Id" />
            <TableColumn<Column> index={Column::Description} label="Description" />
            <TableColumn<Column> index={Column::Cvss} label="CVSS" />
            <TableColumn<Column> index={Column::Published} label="Published" />
            <TableColumn<Column> index={Column::Updated} label="Updated" />
        </TableHeader<Column>>
    );

    let entries = use_memo(props.sbom.clone(), |sbom| sbom.details.clone());

    let (entries, _onexpand) = use_table_data(MemoizedTableModel::new(entries));

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<SbomReportVulnerability>>>
            {header}
            {entries}
            mode={TableMode::Default}
        />
    )
}
