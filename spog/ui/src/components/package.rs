use std::{rc::Rc, str::FromStr};

use packageurl::PackageUrl;
use patternfly_yew::{
    next::{
        use_table_data, Cell, CellContext, ColumnWidth, MemoizedTableModel, Table, TableColumn, TableEntryRenderer,
        TableHeader, Toolbar, ToolbarContent, UseTableData,
    },
    prelude::*,
};
use spog_model::prelude::*;
use url::Url;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncHandleDeps};
use yew_nested_router::components::Link;

use crate::{
    backend::{Endpoint, PackageService, SearchOptions},
    components::common::SafeHtml,
    hooks::use_backend,
    pages::AppRoute,
};

#[derive(PartialEq, Properties)]
pub struct PackageSearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>>,

    pub query: Option<String>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,
}

#[function_component(PackageSearch)]
pub fn package_search(props: &PackageSearchProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(|backend| PackageService::new((**backend).clone()), backend.clone());

    let offset = use_state_eq(|| 0);
    let limit = use_state_eq(|| 10);

    // the active query
    let state = use_state_eq(|| {
        // initialize with the state from history, or with a reasonable default
        props.query.clone().unwrap_or_else(|| {
            gloo_utils::history()
                .state()
                .ok()
                .and_then(|state| state.as_string())
                .unwrap_or_else(String::default)
        })
    });

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |(state, offset, limit)| async move {
                service
                    .search_packages(
                        &state,
                        &SearchOptions {
                            offset: Some(offset),
                            limit: Some(limit),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            ((*state).clone(), *offset, *limit),
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
    let onlimit = {
        let limit = limit.clone();
        Callback::from(move |n| {
            limit.set(n);
        })
    };
    let onnavigation = {
        if let Some(total) = total {
            let offset = offset.clone();

            let limit = limit.clone();
            Callback::from(move |nav| {
                let o = match nav {
                    Navigation::First => 0,
                    Navigation::Last => total - *limit,
                    Navigation::Next => *offset + *limit,
                    Navigation::Previous => *offset - *limit,
                    Navigation::Page(n) => *limit * n - 1,
                };
                offset.set(o);
            })
        } else {
            Callback::default()
        }
    };

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
                        <Pagination
                            total_entries={total}
                            selected_choice={*limit}
                            offset={*offset}
                            entries_per_page_choices={vec![10, 25, 50]}
                            {onnavigation}
                            {onlimit}
                        >
                        </Pagination>
                    </ToolbarItem>

                </ToolbarContent>
                // <ToolbarContent> { for filters.into_iter() } </ToolbarContent>
            </Toolbar>

        </>
    )
}

#[derive(Debug, Properties)]
pub struct PackageResultProperties {
    pub result: SearchResult<Rc<Vec<PackageSummary>>>,
}

impl PartialEq for PackageResultProperties {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.result, &other.result)
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Name,
    Supplier,
    Download,
    Dependencies,
    Advisories,
    Version,
}

#[derive(Clone)]
pub struct PackageEntry {
    url: Option<Url>,
    package: PackageSummary,
}

impl TableEntryRenderer<Column> for PackageEntry {
    fn render_cell(&self, context: &CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => html!(&self.package.name).into(),
            Column::Supplier => html!(&self.package.supplier).into(),
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
            Column::Dependencies => html!(&self.package.dependencies.len()).into(),
            Column::Advisories => {
                html!(<Link<AppRoute> target={AppRoute::Advisory { query: format!("affected:\"{}\"", self.package.purl)}}>{self.package.advisories.len()}</Link<AppRoute>>).into()
            }
            Column::Version => html!(&self.package.version).into(),
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!(<PackageDetails package={Rc::new(self.clone())} />);
        vec![Span::max(html)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(PackageResult)]
pub fn package_result(props: &PackageResultProperties) -> Html {
    let backend = use_backend();
    let entries: Vec<PackageEntry> = props
        .result
        .result
        .iter()
        .map(|pkg| {
            let url = backend.join(Endpoint::Api, &pkg.href).ok();
            PackageEntry {
                package: pkg.clone(),
                url,
            }
        })
        .collect();

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new(entries)));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Name" index={Column::Name} width={ColumnWidth::Percent(15)}/>
            <TableColumn<Column> label="Version" index={Column::Version} width={ColumnWidth::Percent(20)}/>
            <TableColumn<Column> label="Supplier" index={Column::Supplier} width={ColumnWidth::Percent(20)}/>
            <TableColumn<Column> label="Download" index={Column::Download} width={ColumnWidth::Percent(15)}/>
            <TableColumn<Column> label="Dependencies" index={Column::Dependencies} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Advisories" index={Column::Advisories} width={ColumnWidth::Percent(10)}/>
        </TableHeader<Column>>
    };

    html!(
         <Table<Column, UseTableData<Column, MemoizedTableModel<PackageEntry>>>
             mode={TableMode::CompactExpandable}
             {header}
             {entries}
             {onexpand}
         />
    )
}

#[derive(Clone, Properties)]
pub struct PackageDetailsProps {
    pub package: Rc<PackageEntry>,
}

impl PartialEq for PackageDetailsProps {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.package, &other.package)
    }
}

#[function_component(PackageDetails)]
pub fn package_details(props: &PackageDetailsProps) -> Html {
    let package = use_memo(|props| props.package.clone(), props.clone());
    let mut snippet = package.package.snippet.clone();
    if snippet.is_empty() {
        snippet = "No description available".to_string();
    }
    html!(
        <Panel>
            <PanelMain>
            <PanelMainBody>
            <SafeHtml html={snippet} />
            </PanelMainBody>
            </PanelMain>
        </Panel>
    )
}
