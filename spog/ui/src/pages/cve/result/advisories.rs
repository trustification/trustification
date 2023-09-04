use crate::pages::{AppRoute, View};
use patternfly_yew::prelude::*;
use spog_model::prelude::AdvisoryOverview;
use std::rc::Rc;
use yew::prelude::*;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties)]
pub struct RelatedAdvisoriesProperties {
    pub advisories: Rc<Vec<AdvisoryOverview>>,
}

#[derive(Copy, Clone, Eq, PartialEq)]
enum Column {
    Id,
    Title,
}

impl TableEntryRenderer<Column> for AdvisoryOverview {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(
                <Link<AppRoute>
                    target={AppRoute::Advisory(View::Content{id: self.id.clone()})}
                >
                    { &self.id }
                </Link<AppRoute>>
            )
            .into(),
            Column::Title => html!(&self.title).into(),
        }
    }
}

#[function_component(RelatedAdvisories)]
pub fn related_advisories(props: &RelatedAdvisoriesProperties) -> Html {
    let (entries, _) = use_table_data(MemoizedTableModel::new(props.advisories.clone()));

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> index={Column::Id} label="ID" />
            <TableColumn<Column> index={Column::Title} label="Name" />
        </TableHeader<Column>>
    );

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<AdvisoryOverview>>>
            {header}
            {entries}
            mode={TableMode::Compact}
        />
    )
}
