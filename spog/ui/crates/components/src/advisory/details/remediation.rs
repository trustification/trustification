use crate::advisory::{csaf_product_status_entry_details, rem_cat_str};
use csaf::vulnerability::Remediation;
use csaf::Csaf;
use patternfly_yew::prelude::*;
use spog_ui_common::utils::OrNone;
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct CsafRemediationTableProperties {
    pub csaf: Rc<Csaf>,
    pub remediations: Option<Vec<Remediation>>,
}

struct RemediationWrapper {
    csaf: Rc<Csaf>,
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
            <Content>
                { self.rem.details.clone() }
                <Title level={Level::H4}>{ "Products" }</Title>
                <List> {
                    for self.rem.product_ids.iter()
                        .flatten()
                        .map(|prod| html_nested!(<ListItem> { csaf_product_status_entry_details(&self.csaf, prod) } </ListItem>))
                } </List>
            </Content>
        );
        vec![Span::max(content)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(CsafRemediationTable)]
pub fn remediation_table(props: &CsafRemediationTableProperties) -> Html {
    let rems = use_memo(props.remediations.clone(), |rems| {
        rems.clone()
            .into_iter()
            .flatten()
            .map(|rem| RemediationWrapper {
                csaf: props.csaf.clone(),
                rem,
            })
            .collect::<Vec<_>>()
    });

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(rems));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Category" index={Column::Category} />
            <TableColumn<Column> label="Date" index={Column::Date} />
        </TableHeader<Column>>
    };

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<RemediationWrapper>>>
            {header}
            {entries}
            mode={TableMode::CompactExpandable}
            {onexpand}
        />
    )
}
