use futures::future::try_join_all;
use patternfly_yew::prelude::*;
use spog_model::{
    prelude::{PackageProductDetails, ProductRelatedToPackage},
    search::SbomSummary,
};
use spog_ui_backend::{use_backend, PackageService};
use spog_ui_components::{async_state_renderer::async_content, pagination::PaginationWrapped};
use spog_ui_navigation::{AppRoute, View};
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::use_async_with_cloned_deps;
use yew_nested_router::components::Link;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(PartialEq)]
pub struct TableData {
    sbom_id: String,
    dependency_type: String,
    sbom: Option<SbomSummary>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Version,
    Supplier,
    Dependency,
}

impl TableEntryRenderer<Column> for TableData {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(
                <Link<AppRoute>
                    target={AppRoute::Sbom(View::Content{id: self.sbom_id.to_string()})}
                >{ self.sbom_id.clone() }</Link<AppRoute>>
            ),
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
                {&self.dependency_type}
            </>),
        }
        .into()
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
                let service = PackageService::new(backend.clone(), access_token.clone());
                let futures = related_products
                    .iter()
                    .map(|related_product| service.get_package(&related_product.sbom_id));
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
    let table_data = use_memo(
        (props.related_products.clone(), props.sboms.clone()),
        |(related_products, sboms)| {
            related_products
                .iter()
                .enumerate()
                .map(|(index, item)| {
                    let sbom_by_index = &sboms[index];

                    TableData {
                        sbom_id: item.sbom_id.clone(),
                        dependency_type: item.dependency_type.clone(),
                        sbom: sbom_by_index.clone(),
                    }
                })
                .collect::<Vec<_>>()
        },
    );

    let total = table_data.len();
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(table_data));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Name" index={Column::Id} />
            <TableColumn<Column> label="Version" index={Column::Version} />
            <TableColumn<Column> label="Supplier" index={Column::Supplier} />
            <TableColumn<Column> label="Dependency" index={Column::Dependency} />
        </TableHeader<Column>>
    };

    let pagination = use_pagination(Some(total), || PaginationControl { page: 1, per_page: 10 });

    html!(
        <div class="pf-v5-u-background-color-100">
            <PaginationWrapped pagination={pagination} total={10}>
                <Table<Column, UseTableData<Column, MemoizedTableModel<TableData>>>
                    {header}
                    {entries}
                    {onexpand}
                />
            </PaginationWrapped>
        </div>
    )
}
