use std::rc::Rc;

use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use url::Url;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncHandleDeps, UseAsyncState};
use yew_nested_router::components::Link;

use crate::{
    backend::{Endpoint, PackageService, SearchOptions},
    components::{common::SafeHtml, simple_pagination::SimplePagination, table_wrapper::TableWrapper},
    hooks::{use_backend::*, use_pagination_state::*},
    pages::{AppRoute, View},
    utils::pagination_to_offset,
};

#[derive(PartialEq, Properties)]
pub struct PackageSearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<PackageSummary>>>, String>>,

    pub query: Option<String>,

    pub pagination: PaginationState,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,
}

#[function_component(PackageSearch)]
pub fn package_search(props: &PackageSearchProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(|backend| PackageService::new(backend.clone()), backend.clone());

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
            move |(state, page, per_page)| async move {
                service
                    .search_packages(
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
            ((*state).clone(), props.pagination.page, props.pagination.per_page),
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
                            page={props.pagination.page}
                            per_page={props.pagination.per_page}
                            on_page_change={&props.pagination.on_page_change}
                            on_per_page_change={&props.pagination.on_per_page_change}
                        />
                    </ToolbarItem>

                </ToolbarContent>
                // <ToolbarContent> { for filters.into_iter() } </ToolbarContent>
            </Toolbar>

        </>
    )
}

#[derive(PartialEq, Properties)]
pub struct PackageResultProperties {
    pub state: UseAsyncState<SearchResult<Rc<Vec<PackageSummary>>>, String>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Name,
    Supplier,
    Created,
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

impl PackageEntry {
    fn package_name(&self) -> Html {
        if self.package.name.is_empty() {
            html!(<i>{ &self.package.id }</i>)
        } else {
            (&self.package.name).into()
        }
    }
}

impl TableEntryRenderer<Column> for PackageEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => {
                html!(
                    <Link<AppRoute>
                        target={AppRoute::Package(View::Content{id: self.package.id.clone()})}
                    >{ self.package_name() }</Link<AppRoute>>
                ).into()
            },
            Column::Supplier => html!(&self.package.supplier).into(),
            Column::Created => html!(self.package.created.date().to_string()).into(),
            Column::Download => html!(
                if let Some(url) = &self.url {
                    <a href={url.as_str().to_string()} target="_blank">
                        <Button icon={Icon::Download} variant={ButtonVariant::Plain} />
                    </a>
                }
            ).into(),
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
    let data = match &props.state {
        UseAsyncState::Ready(Ok(val)) => {
            let data: Vec<PackageEntry> = val
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
            Some(data)
        }
        _ => None,
    };

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new(data.unwrap_or_default())));

    let header = vec![
        yew::props!(TableColumnProperties<Column> {
            index: Column::Name,
            label: "Name",
            width: ColumnWidth::Percent(15)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Version,
            label: "Version",
            width: ColumnWidth::Percent(20)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Supplier,
            label: "Supplier",
            width: ColumnWidth::Percent(20)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Created,
            label: "Created",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Dependencies,
            label: "Dependencies",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Advisories,
            label: "Advisories",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Download,
            label: "Download",
            width: ColumnWidth::FitContent
        }),
    ];

    html!(
        <TableWrapper<Column, UseTableData<Column, MemoizedTableModel<PackageEntry>>>
            loading={&props.state.is_processing()}
            error={props.state.error().map(|val| val.clone())}
            empty={entries.is_empty()}
            header={header}
        >
            <Table<Column, UseTableData<Column, MemoizedTableModel<PackageEntry>>>
                mode={TableMode::Expandable}
                {entries}
                {onexpand}
            />
        </TableWrapper<Column, UseTableData<Column, MemoizedTableModel<PackageEntry>>>>
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
    let mut snippet = props.package.package.snippet.clone();

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
