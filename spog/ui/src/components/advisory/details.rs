use std::ops::Deref;
use std::rc::Rc;

use crate::{
    backend::VexService,
    components::{
        advisory::{CsafNotes, CsafProductStatus, CsafReferences},
        common::CardWrapper,
    },
    hooks::use_backend::use_backend,
};
use csaf::{definitions::Branch, product_tree::ProductTree, vulnerability::Vulnerability, Csaf};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use yew::prelude::*;
use yew_more_hooks::hooks::use_async_with_cloned_deps;

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
    let service = use_memo(|backend| VexService::new(backend.clone()), backend);
    let summary = props.advisory.clone();

    let fetch = {
        use_async_with_cloned_deps(
            move |summary| async move {
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
            Column::Discovery => html!({ OrNone(self.discovery_date) }),
            Column::Release => html!({ OrNone(self.release_date) }),
            Column::Products => html!(
                <CsafProductStatus status={self.product_status.clone()} csaf={self.csaf.clone()} />
            ),
        }
        .into()
    }

    fn render_details(&self) -> Vec<Span> {
        let content = html!(
            <Grid gutter=true>

                <GridItem cols={[8]}>
                    <CardWrapper plain=true title="Product Status">
                        <CsafProductStatus status={self.product_status.clone()} csaf={self.csaf.clone()} />
                    </CardWrapper>
                </GridItem>

                <GridItem cols={[4]}>
                    <CsafNotes plain=true notes={self.notes.clone()} />
                </GridItem>

                <GridItem cols={[6]}>
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

        // TODO: add remediations

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

    // FIXME: figure out why this is required
    let onexpand = onexpand.reform(|x| x);

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<VulnerabilityWrapper>>>
            {mode}
            {header}
            {entries}
            {onexpand}
        />
    )
}

// products

#[derive(PartialEq)]
struct ProductTreeWrapper(ProductTree);

struct BranchWrapper(Branch);

impl TreeTableModel<()> for ProductTreeWrapper {
    fn children(&self) -> Vec<Rc<dyn TreeNode<()>>> {
        self.0
            .branches
            .iter()
            .flat_map(|s| s.0.iter())
            .map(|branch| Rc::new(BranchWrapper(branch.clone())) as Rc<dyn TreeNode<()>>)
            .collect()
    }
}

impl TreeNode<()> for BranchWrapper {
    fn render_cell(&self, _ctx: CellContext<'_, ()>) -> Cell {
        html!(<>
                { &self.0.name } { " " }
                <Label color={Color::Blue} label={format!("{:?}", self.0.category)} outline=true compact=true/>
            </>)
        .into()
    }

    fn children(&self) -> Vec<Rc<dyn TreeNode<()>>> {
        self.0
            .branches
            .iter()
            .flat_map(|s| s.0.iter())
            .map(|branch| Rc::new(BranchWrapper(branch.clone())) as Rc<dyn TreeNode<()>>)
            .collect()
    }
}

#[function_component(CsafProductInfo)]
pub fn product_info(props: &CsafProperties) -> Html {
    use patternfly_yew::prelude::TableColumn;

    let model = use_memo(
        |csaf| {
            ProductTreeWrapper(csaf.product_tree.clone().unwrap_or(ProductTree {
                branches: None,
                product_groups: None,
                full_product_names: None,
                relationships: None,
            }))
        },
        props.csaf.clone(),
    );

    let header = html_nested! {
        <TreeTableHeader<()>>
            <TableColumn<()> index={()} label="Name"/>
        </TreeTableHeader<()>>
    };

    html!(
        <TreeTable<(), ProductTreeWrapper>
            mode={TreeTableMode::Compact}
            {header}
            {model}
        />
    )
}
