use crate::{components::cvss::CvssScore, utils::cvss::Cvss};
use csaf::{vulnerability::Vulnerability, Csaf};
use patternfly_yew::{
    next::{
        use_table_data, ColumnWidth, MemoizedTableModel, Table, TableColumn, TableEntryRenderer, TableHeader,
        UseTableData,
    },
    prelude::*,
};
use std::rc::Rc;
use yew::prelude::*;

#[derive(Clone, Properties)]
pub struct CsafDetailsProps {
    pub csaf: Rc<Csaf>,
}

impl PartialEq for CsafDetailsProps {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.csaf, &other.csaf)
    }
}

#[function_component(CsafDetails)]
pub fn csaf_details(props: &CsafDetailsProps) -> Html {
    let vulns = use_memo(
        |props| props.csaf.vulnerabilities.clone().unwrap_or_default(),
        props.clone(),
    );

    let products = use_memo(
        |props| props.csaf.product_tree.clone().unwrap_or_default(),
        props.clone(),
    );

    html!(
        <Grid gutter=true>
            <GridItem cols={[12.all()]}>
                <CsafVulnTable entries={vulns}/>
            </GridItem>
            <GridItem cols={[12.all()]}>
                <CsafProductTable entries={vulns}/>
            </GridItem>
        </Grid>
    )
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
    fn render_cell(&self, context: &patternfly_yew::next::CellContext<'_, Column>) -> patternfly_yew::next::Cell {
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
            {onexpand}
        />
    )
}

// products

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProductsColumn {
    Cve,
    Title,
    Cwe,
    Score,
}

#[derive(Properties)]
pub struct CsafProductTableProperties {
    pub entries: Rc<Vec<Vulnerability>>,
}

impl PartialEq for CsafProductTableProperties {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.entries, &other.entries)
    }
}

impl TableEntryRenderer<Column> for Vulnerability {
    fn render_cell(&self, context: &patternfly_yew::next::CellContext<'_, Column>) -> patternfly_yew::next::Cell {
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

#[function_component(CsafProductsTable)]
pub fn products_table(props: &CsafVulnTableProperties) -> Html {
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
            {onexpand}
        />
    )
}
