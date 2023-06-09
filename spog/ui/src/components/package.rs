use crate::backend::{PackageService, SearchOptions};
use crate::hooks::use_backend;
use crate::pages::AppRoute;
use packageurl::PackageUrl;
use patternfly_yew::next::{
    use_table_data, Cell, CellContext, ColumnWidth, MemoizedTableModel, Table, TableColumn, TableEntryRenderer,
    TableHeader, UseTableData,
};
use patternfly_yew::{
    next::{Toolbar, ToolbarContent},
    prelude::*,
};
use spog_model::prelude::*;
use std::rc::Rc;
use std::str::FromStr;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncHandleDeps};
use yew_nested_router::components::Link;

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
                                            <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclear} />
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
    Products,
    Description,
    Vulnerabilities,
    Version,
}

impl TableEntryRenderer<Column> for PackageSummary {
    fn render_cell(&self, context: &CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Name => html!(&self.name).into(),
            Column::Supplier => html!(&self.supplier).into(),
            Column::Products => html!(&self.dependents.len()).into(),
            Column::Description => html!(&self.description).into(),
            Column::Vulnerabilities => {
                html!(<Link<AppRoute> target={AppRoute::Vulnerability { query: format!("affected:\"{}\"", self.purl)}}>{self.vulnerabilities.len()}</Link<AppRoute>>).into()
            }
            Column::Version => {
                if let Ok(purl) = PackageUrl::from_str(&self.purl) {
                    if let Some(version) = purl.version() {
                        html!(version).into()
                    } else {
                        html!().into()
                    }
                } else {
                    html!().into()
                }
            }
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!(); //<Details vuln={Rc::new(self.clone())} />);
        vec![Span::max(html)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(false)
    }
}

#[function_component(PackageResult)]
pub fn package_result(props: &PackageResultProperties) -> Html {
    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(props.result.result.clone()));

    let header = html_nested! {
        <TableHeader<Column>>
            <TableColumn<Column> label="Name" index={Column::Name} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Version" index={Column::Version} width={ColumnWidth::Percent(15)}/>
            <TableColumn<Column> label="Supplier" index={Column::Supplier} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Products" index={Column::Products} width={ColumnWidth::Percent(10)}/>
            <TableColumn<Column> label="Description" index={Column::Description} width={ColumnWidth::Percent(40)}/>
            <TableColumn<Column> label="Vulnerabilities" index={Column::Vulnerabilities} width={ColumnWidth::Percent(15)}/>
        </TableHeader<Column>>
    };

    html!(
         <Table<Column, UseTableData<Column, MemoizedTableModel<PackageSummary>>>
             mode={TableMode::CompactExpandable}
             {header}
             {entries}
             {onexpand}
         />
    )
}
