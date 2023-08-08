mod product;
mod remediation;

pub use product::*;
pub use remediation::*;

use std::ops::Deref;
use std::rc::Rc;

use crate::{
    backend::VexService,
    components::{
        advisory::{CsafNotes, CsafProductStatus, CsafReferences},
        common::CardWrapper,
    },
    hooks::use_backend,
    utils::time::chrono_date,
};
use csaf::{vulnerability::Vulnerability, Csaf};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use yew::prelude::*;
use yew_more_hooks::hooks::use_async_with_cloned_deps;
use yew_oauth2::prelude::use_latest_access_token;

use crate::utils::OrNone;
use crate::{components::common::SafeHtml, components::cvss::Cvss3};

#[derive(Clone, Properties)]
pub struct AdvisoryDetailsProps {
    pub advisory: Rc<AdvisorySummary>,
}

impl PartialEq for AdvisoryDetailsProps {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.advisory, &other.advisory)
    }
}

#[function_component(AdvisoryDetails)]
pub fn csaf_details(props: &AdvisoryDetailsProps) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let summary = props.advisory.clone();

    let fetch = {
        use_async_with_cloned_deps(
            move |summary| async move {
                let service = VexService::new(backend.clone(), access_token);
                service
                    .lookup(&summary)
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            (*summary).clone(),
        )
    };

    if let Some(Some(csaf)) = fetch.data() {
        let snippet = summary.desc.clone();
        html!(
            <Panel>
                <PanelMain>
                <PanelMainBody>
                <SafeHtml html={snippet} />
                <CsafVulnTable csaf={csaf.clone()}/>
                </PanelMainBody>
                </PanelMain>
            </Panel>
        )
    } else {
        html!(<></>)
    }
}

// vulns

#[derive(Clone, Copy, PartialEq, Eq)]
enum Column {
    Cve,
    Title,
    Cwe,
    Score,
    Discovery,
    Release,
    Products,
}

#[derive(PartialEq, Properties)]
pub struct CsafProperties {
    pub csaf: Rc<Csaf>,
}

pub struct VulnerabilityWrapper {
    vuln: Vulnerability,
    csaf: Rc<Csaf>,
}

impl Deref for VulnerabilityWrapper {
    type Target = Vulnerability;

    fn deref(&self) -> &Self::Target {
        &self.vuln
    }
}

impl TableEntryRenderer<Column> for VulnerabilityWrapper {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Cve => html!({ OrNone(self.cve.clone()) }),
            Column::Title => self.title.clone().map(Html::from).unwrap_or_default(),
            Column::Score => self
                .scores
                .clone()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|s| s.cvss_v3)
                .map(|cvss| html!(<Cvss3 {cvss}/>))
                .collect::<Html>(),
            Column::Cwe => OrNone(self.cwe.clone().map(|cwe| {
                html!(
                    <Tooltip text={cwe.name}>
                        {cwe.id}
                    </Tooltip>
                )
            }))
            .into(),
            Column::Discovery => html!({ OrNone(self.discovery_date).map(chrono_date) }),
            Column::Release => html!({ OrNone(self.release_date).map(chrono_date) }),
            Column::Products => html!(
                <CsafProductStatus status={self.product_status.clone()} csaf={self.csaf.clone()} overview=true />
            ),
        }
        .into()
    }

    fn render_details(&self) -> Vec<Span> {
        let content = html!(
            <Grid gutter=true>

                <GridItem cols={[7]}>
                    <CardWrapper plain=true title="Product Status">
                        <CsafProductStatus status={self.product_status.clone()} csaf={self.csaf.clone()} overview=false />
                    </CardWrapper>
                </GridItem>

                <GridItem cols={[5]}>
                    <CardWrapper plain=true title="Remediations">
                        <CsafRemediationTable csaf={self.csaf.clone()} remediations={self.remediations.clone()} />
                    </CardWrapper>
                </GridItem>

                <GridItem cols={[6]}>
                    <CsafNotes plain=true notes={self.notes.clone()} />
                </GridItem>

                <GridItem cols={[4]}>
                    <CardWrapper plain=true title="IDs">
                        if let Some(ids) = &self.ids {
                            <List>
                                { for ids.iter().map(|id|{
                                    html!(<>{&id.text}  {" ("} { &id.system_name } {")"}</>)
                                })}
                            </List>
                        }
                    </CardWrapper>
                </GridItem>

                <GridItem cols={[6]}>
                    <CsafReferences plain=true references={self.references.clone()} />
                </GridItem>

            </Grid>

        );

        vec![Span::max(content)]
    }
}

#[derive(PartialEq, Properties)]
pub struct CsafVulnTableProperties {
    pub csaf: Rc<Csaf>,
    #[prop_or_default]
    pub expandable: bool,
}

#[function_component(CsafVulnTable)]
pub fn vulnerability_table(props: &CsafVulnTableProperties) -> Html {
    let vulns = use_memo(
        |csaf| {
            csaf.vulnerabilities
                .clone()
                .into_iter()
                .flatten()
                .map(|vuln| VulnerabilityWrapper {
                    vuln,
                    csaf: csaf.clone(),
                })
                .collect::<Vec<_>>()
        },
        props.csaf.clone(),
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(vulns));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="CVE ID" index={Column::Cve} />
            <TableColumn<Column> label="Title" index={Column::Title} />
            <TableColumn<Column> label="Discovery" index={Column::Discovery} />
            <TableColumn<Column> label="Release" index={Column::Release} />
            <TableColumn<Column> label="Score" index={Column::Score} />
            <TableColumn<Column> label="CWE" index={Column::Cwe} />
            { for (!props.expandable).then(|| html_nested!(<TableColumn<Column> label="Products" index={Column::Products} />))}
        </TableHeader<Column>>
    };

    let mode = match props.expandable {
        true => TableMode::CompactExpandable,
        false => TableMode::Compact,
    };

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<VulnerabilityWrapper>>>
            {mode}
            {header}
            {entries}
            {onexpand}
        />
    )
}
