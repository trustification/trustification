use crate::components::advisory::rem_cat_str;
use crate::utils::OrNone;
use csaf::vulnerability::Remediation;
use csaf::Csaf;
use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct CsafRemediationTableProperties {
    pub csaf: Rc<Csaf>,
    pub remediations: Option<Vec<Remediation>>,
}

struct RemediationWrapper {
    rem: Remediation,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Column {
    Category,
    Date,
}

impl TableEntryRenderer<Column> for RemediationWrapper {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Category => match &self.rem.url {
                Some(url) => {
                    html!(
                        <a class="pf-v5-c-button pf-m-inline pf-m-link" href={url.to_string()} target="_blank">
                            { rem_cat_str(&self.rem.category) }
                            { " " }
                            { Icon::ExternalLinkAlt }
                        </a>)
                }
                None => html!({ rem_cat_str(&self.rem.category) }),
            },
            Column::Date => html!({ OrNone(self.rem.date) }),
        }
        .into()
    }

    fn render_details(&self) -> Vec<Span> {
        let content = html!(
            <>
                { self.rem.details.clone() }
            </>
        );
        vec![Span::max(content)]
    }
}

#[function_component(CsafRemediationTable)]
pub fn remediation_table(props: &CsafRemediationTableProperties) -> Html {
    let rems = use_memo(
        |rems| {
            rems.clone()
                .into_iter()
                .flatten()
                .map(|rem| RemediationWrapper { rem })
                .collect::<Vec<_>>()
        },
        props.remediations.clone(),
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(rems));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Category" index={Column::Category} />
            <TableColumn<Column> label="Date" index={Column::Date} />
        </TableHeader<Column>>
    };

    // FIXME: figure out why this is required
    let onexpand = onexpand.reform(|x| x);

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<RemediationWrapper>>>
            {header}
            {entries}
            mode={TableMode::CompactExpandable}
            {onexpand}
        />
    )
}
