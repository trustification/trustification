use futures::future::try_join_all;
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use spog_model::{
    prelude::{PackageProductDetails, ProductRelatedToPackage},
    search::SbomSummary,
};
use spog_ui_backend::{use_backend, SBOMService};
use spog_ui_common::use_apply_pagination;
use spog_ui_components::{async_state_renderer::async_content, pagination::PaginationWrapped};
use spog_ui_navigation::{AppRoute, View};
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::use_async_with_cloned_deps;
use yew_nested_router::components::Link;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(Clone, PartialEq)]
pub struct TableData {
    sbom_uid: String,
    backtraces: Vec<Vec<PackageUrl<'static>>>,
    sbom: Option<SbomSummary>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Name,
    Version,
    Supplier,
    Dependency,
}

impl TableEntryRenderer<Column> for TableData {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => html!({
                match &self.sbom {
                    Some(sbom) => html!(
                        <Link<AppRoute>
                            target={AppRoute::Sbom(View::Content{id: sbom.id.clone()})}
                        >{sbom.name.clone()}</Link<AppRoute>>
                    ),
                    // missing source
                    None => html!({ self.sbom_uid.clone() }),
                }
            }),
            Column::Version => html!(<>
                if let Some(sbom) = &self.sbom {
                    {&sbom.version}
                }
            </>),
            Column::Supplier => html!(<>
                if let Some(sbom) = &self.sbom {
                    {&sbom.supplier}
                }
            </>),
            Column::Dependency => html!(<>
                {dependency_type(&self.backtraces)}
            </>),
        }
        .into()
    }

    fn render_details(&self) -> Vec<Span> {
        let content = html!(<>
            <List>
                { for self.backtraces.iter().map(|trace| html_nested!(
                    <ListItem>
                        { for trace.iter().enumerate().map(|(n, purl)| html!(
                            <>
                                if n > 0 {
                                    { " » " }
                                }
                                { purl.to_string() }
                            </>
                        )) }
                    </ListItem>
                ))}
            </List>
        </>);
        vec![Span::max(content)]
    }
}

fn dependency_type(backtraces: &Vec<Vec<PackageUrl>>) -> &'static str {
    let mut direct = false;
    let mut transitive = false;

    for trace in backtraces {
        match trace.is_empty() {
            true => direct = true,
            false => transitive = true,
        }
    }

    match (direct, transitive) {
        (_, false) => "Direct",
        (false, true) => "Transitive",
        (true, true) => "Direct, Transitive",
    }
}

#[derive(PartialEq, Properties)]
pub struct RelatedProductsProperties {
    pub related_products_details: Rc<PackageProductDetails>,
}

#[function_component(RelatedProducts)]
pub fn related_products(props: &RelatedProductsProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let sboms = {
        let backend = backend.clone();
        let access_token = access_token.clone();
        use_async_with_cloned_deps(
            move |related_products| async move {
                let service = SBOMService::new(backend.clone(), access_token.clone());
                let futures = related_products
                    .iter()
                    .map(|related_product| service.get_package(&related_product.sbom_uid));
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
            props.related_products_details.related_products.clone(),
        )
    };

    match props.related_products_details.related_products.is_empty() {
        true => html!(
            <Panel>
                <PanelMain>
                    <Bullseye>
                        <EmptyState
                            title="No related products"
                            icon={Icon::Search}
                        >
                            { "No related products have been found." }
                        </EmptyState>
                    </Bullseye>
                </PanelMain>
            </Panel>
        ),
        false => html!(
            <>
                { async_content(&*sboms, |sboms| html!(<RelatedProductsTable {sboms} related_products={props.related_products_details.related_products.clone()} />)) }
            </>
        ),
    }
}

// Table

#[derive(PartialEq, Properties)]
pub struct RelatedProductsTableProperties {
    pub related_products: Vec<ProductRelatedToPackage>,
    pub sboms: Rc<Vec<Option<SbomSummary>>>,
}

#[function_component(RelatedProductsTable)]
pub fn related_products_table(props: &RelatedProductsTableProperties) -> Html {
    let entries = use_memo(
        (props.related_products.clone(), props.sboms.clone()),
        |(related_products, sboms)| {
            related_products
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let sbom_by_index = &sboms[index];

                    TableData {
                        sbom_uid: item.sbom_uid.clone(),
                        backtraces: item.backtraces.clone(),
                        sbom: sbom_by_index.clone(),
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
            <TableColumn<Column> label="Name" index={Column::Name} />
            <TableColumn<Column> label="Version" index={Column::Version} />
            <TableColumn<Column> label="Supplier" index={Column::Supplier} />
            <TableColumn<Column> label="Dependency" index={Column::Dependency} />
        </TableHeader<Column>>
    };

    html!(
        <div class="pf-v5-u-background-color-100">
            <PaginationWrapped pagination={pagination} {total}>
                <Table<Column, UseTableData<Column, MemoizedTableModel<TableData>>>
                    mode={TableMode::Expandable}
                    {header}
                    {entries}
                    {onexpand}
                />
            </PaginationWrapped>
        </div>
    )
}
