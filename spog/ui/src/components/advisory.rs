use crate::{
    backend::{Endpoint, SearchOptions, VexService},
    hooks::use_backend::use_backend,
    hooks::use_pagination_state::{use_pagination_state, UsePaginationStateArgs},
    utils::pagination_to_offset,
};

use crate::{components::cvss::CvssScore, components::simple_pagination::SimplePagination, utils::cvss::Cvss};
use patternfly_yew::{
    next::{
        use_table_data, Cell, CellContext, ColumnWidth, MemoizedTableModel, Table, TableColumn, TableEntryRenderer,
        TableHeader, Toolbar, ToolbarContent, UseTableData,
    },
    prelude::*,
};
use spog_model::prelude::*;
use std::rc::Rc;
use url::Url;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncHandleDeps};

use details::AdvisoryDetails;

#[derive(PartialEq, Properties)]
pub struct AdvisorySearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>>,

    pub query: Option<String>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,
}

#[function_component(AdvisorySearch)]
pub fn advisory_search(props: &AdvisorySearchProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(|backend| VexService::new((**backend).clone()), backend.clone());

    let pagination_state = use_pagination_state(|| UsePaginationStateArgs {
        initial_items_per_page: 10,
    });

    // the active query
    let state = use_state_eq(|| {
        // initialize with the state from history, or with a reasonable default
        gloo_utils::history()
            .state()
            .ok()
            .and_then(|state| state.as_string())
            .unwrap_or_else(|| props.query.clone().unwrap_or(String::default()))
    });

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |(state, page, per_page)| async move {
                service
                    .search_advisories(
                        &state,
                        &SearchOptions {
                            offset: Some(pagination_to_offset(page, per_page)),
                            limit: Some(per_page),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            ((*state).clone(), pagination_state.page, pagination_state.per_page),
        )
    };

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (props.callback.clone(), search.clone()),
    );

    // the current value in the text input field
    let text = use_state_eq(|| (*state).clone());

    let onclear = {
        let text = text.clone();
        Callback::from(move |_| {
            text.set(String::new());
        })
    };
    let onset = {
        let state = state.clone();
        let text = text.clone();
        Callback::from(move |()| {
            state.set((*text).clone());
        })
    };

    use_effect_with_deps(
        |query| {
            // store changes to the state in the current history
            let _ = gloo_utils::history().replace_state(&query.into(), "");
        },
        (*state).clone(),
    );

    // pagination

    let total = search.data().and_then(|d| d.total);

    let hidden = text.is_empty();

    // render
    html!(
        <>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarGroup>
                        <ToolbarItem r#type={ToolbarItemType::SearchFilter} width={["600px".to_string()]}>
                            <Form onsubmit={onset.reform(|_|())}>
                                // needed to trigger submit when pressing enter in the search field
                                <input type="submit" hidden=true formmethod="dialog" />
                                <InputGroup>
                                    <TextInputGroup>
                                        <TextInputGroupMain
                                            icon={Icon::Search}
                                            placeholder="Search"
                                            value={(*text).clone()}
                                            oninput={ Callback::from(move |data| text.set(data)) }
                                        />
                                        <TextInputGroupUtilities>
                                            <div hidden={hidden}>
                                                <Button icon={Icon::Times} variant={ButtonVariant::None} onclick={onclear} />
                                            </div>
                                        </TextInputGroupUtilities>
                                        <Button icon={Icon::ArrowRight} variant={ButtonVariant::Control} onclick={onset.reform(|_|())} />
                                    </TextInputGroup>
                                </InputGroup>
                            </Form>
                        </ToolbarItem>
                    </ToolbarGroup>

                    { for props.toolbar_items.iter() }

                    <ToolbarItem r#type={ToolbarItemType::Pagination}>
                        <SimplePagination
                            total_items={total}
                            page={pagination_state.page}
                            per_page={pagination_state.per_page}
                            on_page_change={pagination_state.on_page_change}
                            on_per_page_change={pagination_state.on_per_page_change}
                        />
                    </ToolbarItem>

                </ToolbarContent>
                // <ToolbarContent> { for filters.into_iter() } </ToolbarContent>
            </Toolbar>

        </>
    )
}

#[derive(PartialEq, Properties, Clone)]
pub struct AdvisoryEntry {
    summary: AdvisorySummary,
    url: Option<Url>,
}

#[derive(Debug, Properties)]
pub struct AdvisoryResultProperties {
    pub result: SearchResult<Rc<Vec<AdvisorySummary>>>,
}

impl PartialEq for AdvisoryResultProperties {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.result, &other.result)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Title,
    Revision,
    Download,
    Vulnerabilities,
}

impl TableEntryRenderer<Column> for AdvisoryEntry {
    fn render_cell(&self, context: &CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(&self.summary.id).into(),
            Column::Title => html!(&self.summary.title).into(),
            Column::Revision => {
                let s = if let Ok(s) = self.summary.date.format(&time::format_description::well_known::Rfc3339) {
                    s.to_string()
                } else {
                    self.summary.date.to_string()
                };
                html!(s).into()
            }
            Column::Download => {
                if let Some(url) = &self.url {
                    html!(
                        <a href={url.as_str().to_string()}>
                            <Button icon={Icon::Download} variant={ButtonVariant::Plain} />
                        </a>
                    )
                    .into()
                } else {
                    html!().into()
                }
            }
            Column::Vulnerabilities => {
                let l = self.summary.cves.len();
                html!(if l == 0 {
                    {
                        "N/A"
                    }
                } else {
                    {
                        l.to_string()
                    }
                })
                .into()
            }
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!(<AdvisoryDetails advisory={Rc::new(self.summary.clone())} />);
        vec![Span::max(html)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(AdvisoryResult)]
pub fn vulnerability_result(props: &AdvisoryResultProperties) -> Html {
    let backend = use_backend();
    let entries: Vec<AdvisoryEntry> = props
        .result
        .result
        .iter()
        .map(|summary| {
            let url = backend.join(Endpoint::Api, &summary.href).ok();
            AdvisoryEntry {
                summary: summary.clone(),
                url,
            }
        })
        .collect();

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new(entries)));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="ID" index={Column::Id} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Title" index={Column::Title} width={ColumnWidth::Percent(45)}/>
            <TableColumn<Column> label="Revision" index={Column::Revision} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Download" index={Column::Download} width={ColumnWidth::Percent(5)}/>
            <TableColumn<Column> label="Vulnerabilities" index={Column::Vulnerabilities} width={ColumnWidth::Percent(15)}/>
        </TableHeader<Column>>
    };

    html!(
        <Table<Column, UseTableData<Column, MemoizedTableModel<AdvisoryEntry>>>
            mode={TableMode::CompactExpandable}
            {header}
            {entries}
            {onexpand}
        />
    )
}

mod details {

    use std::rc::Rc;

    use crate::backend::VexService;
    use crate::hooks::use_backend::use_backend;
    use csaf::{definitions::Branch, product_tree::ProductTree, vulnerability::Vulnerability};
    use patternfly_yew::{
        next::{use_table_data, MemoizedTableModel, Table, TableColumn, TableEntryRenderer, TableHeader, UseTableData},
        prelude::*,
    };
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

    impl TreeTableModel for ProductTreeWrapper {
        fn children(&self) -> Vec<Rc<dyn TreeNode>> {
            self.0
                .branches
                .iter()
                .flat_map(|s| s.0.iter())
                .map(|branch| Rc::new(BranchWrapper(branch.clone())) as Rc<dyn TreeNode>)
                .collect()
        }
    }

    impl TreeNode for BranchWrapper {
        fn render_main(&self) -> Cell {
            html!(<>
            { &self.0.name } { " " }
            <Label color={Color::Blue} label={format!("{:?}", self.0.category)} outline=true compact=true/>
        </>)
            .into()
        }

        fn render_cell(&self, ctx: CellContext) -> Cell {
            match ctx.column {
                _ => html!(),
            }
            .into()
        }

        fn children(&self) -> Vec<Rc<dyn TreeNode>> {
            self.0
                .branches
                .iter()
                .flat_map(|s| s.0.iter())
                .map(|branch| Rc::new(BranchWrapper(branch.clone())) as Rc<dyn TreeNode>)
                .collect()
        }
    }

    #[function_component(CsafProductInfo)]
    pub fn product_info(props: &CsafProductInfoProperties) -> Html {
        use patternfly_yew::prelude::TableColumn;

        let header = html_nested! {
            <TreeTableHeader>
                <TableColumn label="Name"/>
            </TreeTableHeader>
        };

        let root = Rc::new(ProductTreeWrapper(props.product.clone()));

        html!(
            <TreeTable<ProductTreeWrapper>
                mode={TreeTableMode::Compact}
                header={header}
                model={root}
            />
        )
    }
}
