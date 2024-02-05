use cyclonedx_bom::external_models::uri::Purl;
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use spog_ui_common::use_apply_pagination;
use std::rc::Rc;
use std::str::FromStr;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct CycloneDxPackagesProperties {
    pub bom: Rc<cyclonedx_bom::prelude::Bom>,
}

#[function_component(CycloneDxPackages)]
pub fn cyclonedx_packages(props: &CycloneDxPackagesProperties) -> Html {
    #[derive(Clone, Eq, PartialEq)]
    enum Column {
        Name,
        Versions,
        Qualifiers,
    }

    #[derive(Clone, Debug, PartialEq)]
    struct TableData {
        name: String,
        version: String,
        purl: Option<Purl>,
    }

    impl TableEntryRenderer<Column> for TableData {
        fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
            let package_url = self.purl.as_ref().and_then(|purl| {
                let purl_string = purl.to_string();
                PackageUrl::from_str(&purl_string).ok()
            });

            match context.column {
                Column::Name => {
                    if let Some(pkg) = package_url {
                        html!(<>{&self.name}{" "}<Label compact=true label={pkg.ty().to_string()} /></>)
                    } else {
                        html!(<>{&self.name}</>)
                    }
                }
                Column::Versions => html!(
                    <>{&self.version}</>
                ),
                Column::Qualifiers => {
                    if let Some(pkg) = package_url {
                        html!({ for pkg.qualifiers().iter().map(|(k,v)| html!(<Label label={format!("{k}={v}")} />)) })
                    } else {
                        html!(<></>)
                    }
                }
            }
            .into()
        }
    }

    let header = html_nested!(
        <TableHeader<Column>>
            <TableColumn<Column> width={ColumnWidth::Percent(30)} index={Column::Name} label="Name" />
            <TableColumn<Column> width={ColumnWidth::Percent(20)} index={Column::Versions} label="Versions" />
            <TableColumn<Column> width={ColumnWidth::Percent(50)} index={Column::Qualifiers} label="Qualifiers" />
        </TableHeader<Column>>
    );

    let table_data = use_memo(props.bom.clone(), |bom| {
        bom.components.as_ref().map_or(vec![], |e| {
            e.0.iter()
                .map(|c| TableData {
                    name: c.name.to_string(),
                    version: c.version.to_string(),
                    purl: c.purl.clone(),
                })
                .collect::<Vec<_>>()
        })
    });

    let filter = use_state_eq(String::new);

    let filtered_table_data = {
        use_memo((table_data, (*filter).clone()), move |(packages, filter)| {
            let packages = packages
                .iter()
                .filter(|p| filter.is_empty() || { p.name.contains(filter) })
                .cloned()
                .collect::<Vec<_>>();

            packages
        })
    };

    //
    let total = filtered_table_data.len();

    let pagination = use_pagination(Some(total), Default::default);
    let entries = use_apply_pagination(filtered_table_data, pagination.control);
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(entries));

    let onclearfilter = use_callback(filter.clone(), |_, filter| filter.set(String::new()));
    let onsetfilter = use_callback(filter.clone(), |value: String, filter| {
        filter.set(value.trim().to_string())
    });

    html!(
        <>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarItem r#type={ToolbarItemType::SearchFilter}>
                        <TextInputGroup>
                            <TextInputGroupMain
                                placeholder="Filter"
                                icon={Icon::Search}
                                value={(*filter).clone()}
                                onchange={onsetfilter}
                            />
                            if !filter.is_empty() {
                                <TextInputGroupUtilities>
                                    <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclearfilter}/>
                                </TextInputGroupUtilities>
                            }
                        </TextInputGroup>
                    </ToolbarItem>

                    <ToolbarItem r#type={ToolbarItemType::Pagination}>
                        <SimplePagination pagination={pagination.clone()} {total} />
                    </ToolbarItem>
                </ToolbarContent>
            </Toolbar>

            <Table<Column, UseTableData<Column, MemoizedTableModel<TableData>>>
                mode={TableMode::Compact}
                {header}
                {entries}
                {onexpand}
            />

            <SimplePagination
                {pagination}
                {total}
                position={PaginationPosition::Bottom}
            />
        </>
    )
}
