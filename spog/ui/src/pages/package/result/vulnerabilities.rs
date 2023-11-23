use futures::future::try_join_all;
use patternfly_yew::prelude::*;
use spog_model::prelude::{CveSearchDocument, PackageInfo, V11yRef};
use spog_ui_backend::{use_backend, CveService};
use spog_ui_common::{use_apply_pagination, utils::cvss::Cvss, utils::time::date, utils::OrNone};
use spog_ui_components::{async_state_renderer::async_content, cvss::CvssScore, pagination::PaginationWrapped};
use spog_ui_navigation::{AppRoute, View};
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::use_async_with_cloned_deps;
use yew_nested_router::components::Link;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, PartialEq)]
pub struct TableData {
    id: String,
    cve: Option<CveSearchDocument>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Description,
    Severity,
    DatePublished,
}

impl TableEntryRenderer<Column> for TableData {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(
                <Link<AppRoute>
                    target={AppRoute::Cve(View::Content{id: self.id.clone()})}
                >{ self.id.clone() }</Link<AppRoute>>
            ),
            Column::Description => html!( <>
                if let Some(cve) = &self.cve {
                    if let Some(title) = &cve.title {
                        { title }
                    } else {
                        { for cve.descriptions.iter() }
                    }
                }
            </>),
            Column::Severity => html!( <>
                if let Some(cve) = &self.cve {
                    if let Some(score)= &cve.cvss3x_score {
                        <CvssScore cvss={Cvss{score: (*score) as _}} />
                    }
                }
            </>),
            Column::DatePublished => html!( <>
                if let Some(cve) = &self.cve {
                    {OrNone(cve.date_published).map(date)}
                }
            </>),
        }
        .into()
    }
}

#[derive(PartialEq, Properties)]
pub struct VulnerabilitiesProperties {
    pub package: Rc<PackageInfo>,
}

#[function_component(Vulnerabilities)]
pub fn vulnerabilities(props: &VulnerabilitiesProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let cves_detail = {
        let backend = backend.clone();
        let access_token = access_token.clone();
        use_async_with_cloned_deps(
            move |vulnerabilities| async move {
                let service = CveService::new(backend.clone(), access_token.clone());
                let futures = vulnerabilities.iter().map(|vuln| service.get_from_index(&vuln.cve));
                try_join_all(futures)
                    .await
                    .map(|vec| {
                        vec.iter()
                            .map(|search_result| {
                                if search_result.result.len() == 1 {
                                    let cve = &search_result.result[0];
                                    Some(cve.clone())
                                } else {
                                    None
                                }
                            })
                            .collect::<Vec<_>>()
                    })
                    .map(Rc::new)
                    .map_err(|err| err.to_string())
            },
            props.package.vulnerabilities.clone(),
        )
    };

    match props.package.vulnerabilities.is_empty() {
        true => html!(
            <Panel>
                <PanelMain>
                    <Bullseye>
                        <EmptyState
                            title="No related vulnerabilities"
                            icon={Icon::Search}
                        >
                            { "No related vulnerabilities have been found." }
                        </EmptyState>
                    </Bullseye>
                </PanelMain>
            </Panel>
        ),
        false => html!(
            <>
                { async_content(&*cves_detail, |cves_detail| html!(<VulnerabilitiesTable vulnerabilities={props.package.vulnerabilities.clone()}  details={cves_detail} />)) }
            </>
        ),
    }
}

// Table

#[derive(PartialEq, Properties)]
pub struct VulnerabilitiesTableProperties {
    pub vulnerabilities: Vec<V11yRef>,
    pub details: Rc<Vec<Option<CveSearchDocument>>>,
}

#[function_component(VulnerabilitiesTable)]
pub fn vulnerabilities_table(props: &VulnerabilitiesTableProperties) -> Html {
    let entries = use_memo(
        (props.vulnerabilities.clone(), props.details.clone()),
        |(vulnerabilities, details)| {
            vulnerabilities
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let detail_by_index = &details[index];

                    TableData {
                        id: item.cve.clone(),
                        cve: detail_by_index.clone(),
                    }
                })
                .collect::<Vec<_>>()
        },
    );

    let total = entries.len();
    let pagination = use_pagination(Some(total), Default::default);
    let entries = use_apply_pagination(entries, pagination.control);
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="ID" index={Column::Id} />
            <TableColumn<Column> label="Description" index={Column::Description} />
            <TableColumn<Column> label="Severity" index={Column::Severity} />
            <TableColumn<Column> label="Date published" index={Column::DatePublished} />
        </TableHeader<Column>>
    };

    html!(
        <div class="pf-v5-u-background-color-100">
            <PaginationWrapped pagination={pagination} {total}>
                <Table<Column, UseTableData<Column, MemoizedTableModel<TableData>>>
                    {header}
                    {entries}
                    {onexpand}
                />
            </PaginationWrapped>
        </div>
    )
}
