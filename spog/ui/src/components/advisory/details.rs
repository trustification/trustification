use std::rc::Rc;

use crate::backend::VexService;
use crate::hooks::use_backend::use_backend;
use csaf::{definitions::Branch, product_tree::ProductTree, vulnerability::Vulnerability};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use yew::prelude::*;
use yew_more_hooks::hooks::use_async_with_cloned_deps;

use crate::{components::common::SafeHtml, components::cvss::CvssScore, utils::cvss::Cvss};

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
    let service = use_memo(|backend| VexService::new((**backend).clone()), backend.clone());
    let summary = props.advisory.clone();

    let fetch = {
        let service = service.clone();
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
        let vulns = Rc::new(csaf.vulnerabilities.clone().unwrap_or_default());
        let product = Rc::new(csaf.product_tree.clone().unwrap_or_else(|| ProductTree {
            branches: None,
            product_groups: None,
            full_product_names: None,
            relationships: None,
        }));

        let snippet = summary.desc.clone();
        html!(
            <Panel>
                <PanelMain>
                <PanelMainBody>
                <SafeHtml html={snippet} />
                <Grid gutter=true>
                    <GridItem cols={[6.all()]}>
                        <CsafVulnTable entries={vulns}/>
                    </GridItem>
                    <GridItem cols={[6.all()]}>
                        <CsafProductInfo {product}/>
                    </GridItem>
                </Grid>
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
}

#[derive(Properties)]
pub struct CsafVulnTableProperties {
    pub entries: Rc<Vec<Vulnerability>>,
}

impl PartialEq for CsafVulnTableProperties {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.entries, &other.entries)
    }
}

impl TableEntryRenderer<Column> for Vulnerability {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Cve => self
                .cve
                .clone()
                .map(|cve| html!(cve))
                .unwrap_or_else(|| html!(<i>{"N/A"}</i>)),
            Column::Title => self.title.clone().map(Html::from).unwrap_or_default(),
            Column::Score => self
                .scores
                .clone()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|s| s.cvss_v3)
                .map(|s| Cvss {
                    score: s.score().value() as f32,
                    status: String::new(),
                })
                .map(|cvss| html!(<CvssScore {cvss}/>))
                .collect::<Html>(),
            Column::Cwe => self
                .cwe
                .clone()
                .map(|cwe| {
                    html!(<Tooltip text={cwe.name}>
                        {cwe.id}
                    </Tooltip>)
                })
                .unwrap_or_else(|| html!(<i>{"N/A"}</i>)),
        }
        .into()
    }
}

#[function_component(CsafVulnTable)]
pub fn vulnerability_table(props: &CsafVulnTableProperties) -> Html {
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(props.entries.clone()));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="CVE ID" index={Column::Cve} />
            <TableColumn<Column> label="Title" index={Column::Title} />
            <TableColumn<Column> label="Score" index={Column::Score} />
            <TableColumn<Column> label="CWE" index={Column::Cwe} />
        </TableHeader<Column>>
    };

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<Vulnerability>>>
            mode={TableMode::Compact}
            {header}
            {entries}
            onexpand={(*onexpand).clone()}
        />
    )
}

// products

#[derive(Properties)]
pub struct CsafProductInfoProperties {
    pub product: Rc<ProductTree>,
}

impl PartialEq for CsafProductInfoProperties {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.product, &other.product)
    }
}

struct ProductTreeWrapper(Rc<ProductTree>);

impl PartialEq for ProductTreeWrapper {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.0, &other.0)
    }
}

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
pub fn product_info(props: &CsafProductInfoProperties) -> Html {
    use patternfly_yew::prelude::TableColumn;

    let header = html_nested! {
        <TreeTableHeader<()>>
            <TableColumn<()> index={()} label="Name"/>
        </TreeTableHeader<()>>
    };

    let root = Rc::new(ProductTreeWrapper(props.product.clone()));

    html!(
        <TreeTable<(), ProductTreeWrapper>
            mode={TreeTableMode::Compact}
            header={header}
            model={root}
        />
    )
}
