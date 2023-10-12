use patternfly_yew::prelude::*;
use spog_model::prelude::AdvisorySummary;
use spog_ui_components::{severity::Severity, time::Date};
use spog_ui_navigation::{AppRoute, View};
use std::rc::Rc;
use yew::prelude::*;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties)]
pub struct RelatedAdvisoriesProperties {
    pub advisories: Rc<Vec<AdvisorySummary>>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Column {
    Id,
    Title,
    AggregatedSeverity,
    Revision,
    Vulnerabilities,
}

#[function_component(RelatedAdvisories)]
pub fn related_advisories(props: &RelatedAdvisoriesProperties) -> Html {
    let (entries, _) = use_table_data(MemoizedTableModel::new(props.advisories.clone()));

    impl TableEntryRenderer<Column> for AdvisorySummary {
        fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
            match context.column {
                Column::Id => {
                    html! (
                        <Link<AppRoute> target={AppRoute::Advisory(View::Content {id: self.id.clone()})} >
                            { self.id.clone() }
                        </Link<AppRoute>>
                    )
                }
                Column::Title => html!(self.title.clone()),
                Column::AggregatedSeverity => html!(<Severity severity={self.severity.clone()} />),
                Column::Revision => html!(<Date timestamp={self.date} />),
                Column::Vulnerabilities => html!(self.cves.len()),
            }
            .into()
        }
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Id} label="ID" />
            <TableColumn<Column> index={Column::Title} label="Title" />
            <TableColumn<Column> index={Column::AggregatedSeverity} label="Aggregated severity" />
            <TableColumn<Column> index={Column::Revision} label="Revision" />
            <TableColumn<Column> index={Column::Vulnerabilities} label="Vulnerabilities" />
        </TableHeader<Column>>
    );

    match props.advisories.is_empty() {
        true => html!(
            <Panel>
                <PanelMain>
                    <Bullseye>
                        <EmptyState
                            title="No results"
                            icon={Icon::Search}
                        >
                            { "Try a different search expression." }
                        </EmptyState>
                    </Bullseye>
                </PanelMain>
            </Panel>
        ),
        false => html!(
            <Table<Column, UseTableData<Column, MemoizedTableModel<AdvisorySummary>>>
                {header}
                {entries}
                mode={TableMode::Default}
            />
        ),
    }
}
