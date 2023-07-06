use crate::{
    backend::{SearchOptions, VexService},
    components::{search::*, severity::Severity, simple_pagination::SimplePagination},
    hooks::{use_backend::use_backend, use_pagination_state::*},
    utils::pagination_to_offset,
};
use gloo_utils::format::JsValueSerdeExt;
use itertools::Itertools;
use lazy_static::lazy_static;
use patternfly_yew::prelude::*;
use sikula::prelude::Search as _;
use spog_model::prelude::*;
use std::collections::HashSet;
use std::rc::Rc;
use vexination_model::prelude::Vulnerabilities;
use wasm_bindgen::JsValue;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncHandleDeps};

#[derive(PartialEq, Properties)]
pub struct AdvisorySearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>>,

    pub query: Option<String>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,

    #[prop_or_default]
    pub children: Children,
}

#[function_component(AdvisorySearch)]
pub fn advisory_search(props: &AdvisorySearchProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(|backend| VexService::new(backend.clone()), backend.clone());

    // the active query
    let search_params = use_state_eq(|| {
        // initialize with the state from history, properties, or with a reasonable default
        gloo_utils::history()
            .state()
            .ok()
            .and_then(|state| {
                let deser = state.into_serde::<SearchMode<SearchParameters>>();
                log::debug!("Deserialized: {deser:?}");
                deser.ok()
            })
            .or_else(|| {
                props.query.clone().map(|s| {
                    log::debug!("Initial: {s}");
                    match s.is_empty() {
                        true => SearchMode::default(),
                        false => SearchMode::Complex(s),
                    }
                })
            })
            .unwrap_or_else(SearchMode::default)
    });

    let pagination_state = use_pagination_state(|| UsePaginationStateArgs {
        initial_items_per_page: 10,
    });

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |(search_params, page, per_page)| async move {
                service
                    .search_advisories(
                        &search_params.as_str(),
                        &SearchOptions {
                            offset: Some(pagination_to_offset(page, per_page)),
                            limit: Some(per_page),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            (
                (*search_params).clone(),
                pagination_state.page,
                pagination_state.per_page,
            ),
        )
    };

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (props.callback.clone(), search.clone()),
    );

    // the current value in the text input field
    let text = use_state_eq(|| match &*search_params {
        SearchMode::Complex(s) => s.to_string(),
        SearchMode::Simple(s) => s.terms.join(" "),
    });

    // parse filter
    let filter_input_state = use_memo(
        |(simple, text)| match simple {
            true => InputState::Default,
            false => match Vulnerabilities::parse(text) {
                Ok(_) => InputState::Default,
                Err(_) => InputState::Error,
            },
        },
        ((*search_params).is_simple(), (*text).clone()),
    );

    // clear search, keep mode
    let onclear = {
        let text = text.clone();
        let search_params = search_params.clone();
        Callback::from(move |_| {
            text.set(String::new());
            // trigger empty search
            match *search_params {
                SearchMode::Complex(_) => search_params.set(SearchMode::Complex(String::new())),
                SearchMode::Simple(_) => search_params.set(SearchMode::Simple(Default::default())),
            }
        })
    };

    // apply text field to search
    let onset = {
        let search_params = search_params.clone();
        let text = text.clone();
        Callback::from(move |()| {
            let s = (*search_params).clone();
            match s {
                SearchMode::Complex(_) => {
                    search_params.set(SearchMode::Complex((*text).clone()));
                }
                SearchMode::Simple(mut s) => {
                    let text = &*text;
                    s.terms = text.split(" ").map(|s| s.to_string()).collect();
                    search_params.set(SearchMode::Simple(s));
                }
            }
        })
    };

    use_effect_with_deps(
        |search_params| {
            // store changes to the state in the current history
            if let Ok(data) = JsValue::from_serde(search_params) {
                let _ = gloo_utils::history().replace_state(&data, "");
            }
        },
        (*search_params).clone(),
    );

    // pagination

    let total = search.data().and_then(|d| d.total);

    let hidden = text.is_empty();

    // filter

    let filter_expansion = use_state(|| SEARCH.category_labels::<HashSet<_>>());

    // switch

    let simple = search_params.is_simple();

    // toggle search mode: simple <-> complex
    let ontogglesimple = {
        let search_params = search_params.clone();
        let text = text.clone();

        Callback::from(move |state| match state {
            false => {
                let q = (*search_params).as_str().to_string();
                search_params.set(SearchMode::Complex(q.clone()));
                text.set(q);
            }
            true => {
                search_params.set(SearchMode::default());
                text.set(String::new());
            }
        })
    };

    // render
    html!(
        <>

            <Grid>
                <GridItem cols={[2]}>
                    <div style="height: 100%; display: flex; flex-direction: row; align-items: center;">
                        <Title level={Level::H2}>{ "Categories " } <Switch checked={simple} label="Simple" label_off="Complex" onchange={ontogglesimple}/> </Title>
                    </div>
                </GridItem>
                <GridItem cols={[10]}>

                    <Toolbar>
                        <ToolbarContent>
                            <ToolbarGroup variant={GroupVariant::Filter}>
                                <ToolbarItem r#type={ToolbarItemType::SearchFilter} width={["600px".to_string()]}>
                                    <Form onsubmit={onset.reform(|_|())}>
                                        // needed to trigger submit when pressing enter in the search field
                                        <input type="submit" hidden=true formmethod="dialog" />
                                        <InputGroup>
                                            <TextInputGroup>
                                                <TextInput
                                                    icon={Icon::Search}
                                                    placeholder="Search"
                                                    value={(*text).clone()}
                                                    state={*filter_input_state}
                                                    oninput={ Callback::from(move |data| text.set(data)) }
                                                />

                                                if !hidden {
                                                    <TextInputGroupUtilities>
                                                        <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclear} />
                                                    </TextInputGroupUtilities>
                                                }
                                            </TextInputGroup>
                                            <InputGroupItem>
                                                <Button
                                                    disabled={*filter_input_state == InputState::Error}
                                                    icon={Icon::ArrowRight}
                                                    variant={ButtonVariant::Control}
                                                    onclick={onset.reform(|_|())}
                                                />
                                            </InputGroupItem>
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
                                    on_page_change={&pagination_state.on_page_change}
                                    on_per_page_change={&pagination_state.on_per_page_change}
                                />
                            </ToolbarItem>

                        </ToolbarContent>
                    </Toolbar>

                </GridItem>

                <GridItem cols={[2]}>
                    { simple_search(&SEARCH, search_params.clone(), filter_expansion.clone()) }
                </GridItem>

                <GridItem cols={[10]}>
                    { for props.children.iter() }
                </GridItem>

            </Grid>

            <SimplePagination
                position={PaginationPosition::Bottom}
                total_items={total}
                page={pagination_state.page}
                per_page={pagination_state.per_page}
                on_page_change={pagination_state.on_page_change}
                on_per_page_change={pagination_state.on_per_page_change}
            />

        </>
    )
}

lazy_static! {
    static ref SEARCH: Search<SearchParameters> = Search {
        categories: vec![
            SearchCategory {
                title: "Severity",
                options: vec![
                    SearchOption::<SearchParameters>::new_fn(
                        || html!(<Severity severity="Low"/>),
                        |options| options.is_low,
                        |options, value| options.is_low = value
                    ),
                    SearchOption::<SearchParameters>::new_fn(
                        || html!(<Severity severity="Moderate"/>),
                        |options| options.is_moderate,
                        |options, value| options.is_moderate = value
                    ),
                    SearchOption::<SearchParameters>::new_fn(
                        || html!(<Severity severity="Important"/>),
                        |options| options.is_important,
                        |options, value| options.is_important = value
                    ),
                    SearchOption::<SearchParameters>::new_fn(
                        || html!(<Severity severity="Critical"/>),
                        |options| options.is_critical,
                        |options, value| options.is_critical = value
                    )
                ],
            },
            SearchCategory {
                title: "Products",
                options: vec![
                    SearchOption::<SearchParameters>::new_str(
                        "Red Hat Enterprise Linux 7",
                        |options| options.is_rhel7,
                        |options, value| options.is_rhel7 = value
                    ),
                    SearchOption::<SearchParameters>::new_str(
                        "Red Hat Enterprise Linux 8",
                        |options| options.is_rhel8,
                        |options, value| options.is_rhel8 = value
                    ),
                    SearchOption::<SearchParameters>::new_str(
                        "Red Hat Enterprise Linux 9",
                        |options| options.is_rhel9,
                        |options, value| options.is_rhel9 = value
                    ),
                    SearchOption::<SearchParameters>::new_str(
                        "OpenShift Container Platform 4",
                        |options| options.is_ocp4,
                        |options, value| options.is_ocp4 = value
                    ),
                ]
            }
        ]
    };
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SearchParameters {
    terms: Vec<String>,

    is_low: bool,
    is_moderate: bool,
    is_important: bool,
    is_critical: bool,

    is_rhel7: bool,
    is_rhel8: bool,
    is_rhel9: bool,

    is_ocp4: bool,
}

impl ToFilterExpression for SearchParameters {
    fn to_filter_expression(&self) -> String {
        let mut terms = self.terms.clone();

        if self.is_low {
            terms.extend(["severity:Low".to_string()]);
        }

        if self.is_moderate {
            terms.extend(["severity:Moderate".to_string()]);
        }

        if self.is_important {
            terms.extend(["severity:Important".to_string()]);
        }

        if self.is_critical {
            terms.extend(["severity:Critical".to_string()]);
        }

        if self.is_rhel7 {
            terms.extend(rhel7_variants());
        }

        if self.is_rhel8 {
            terms.extend(rhel8_variants());
        }

        if self.is_rhel9 {
            terms.extend(or_group([
                r#"package:"cpe:/a:redhat:enterprise_linux:9::appstream""#.to_string(),
                r#"package:"cpe:/a:redhat:enterprise_linux:9::crb""#.to_string(),
            ]));
        }

        // cpe:/a:redhat:openshift:4.13::el8
        if self.is_ocp4 {
            terms.extend(ocp4_variants());
        }

        or_group(terms).join(" ")
    }
}

/// Create an `OR` group from a list of terms. In case the iterator is empty, return an empty string.
fn or_group(terms: impl IntoIterator<Item = String>) -> impl Iterator<Item = String> {
    let mut terms = terms.into_iter();

    let first = terms.next();
    let (prefix, suffix) = match &first {
        Some(_) => (Some("(".to_string()), Some(")".to_string())),
        None => (None, None),
    };

    prefix
        .into_iter()
        .chain(itertools::intersperse(first.into_iter().chain(terms), "OR".to_string()))
        .chain(suffix)
}

fn rhel7_variants() -> impl Iterator<Item = String> {
    (0..15).into_iter().flat_map(|minor| {
        vec![
            format!(r#"package:"cpe:/o:redhat:rhel_eus:7.{minor}::client""#),
            format!(r#"package:"cpe:/o:redhat:rhel_eus:7.{minor}::worksatation""#),
            format!(r#"package:"cpe:/o:redhat:rhel_eus:7.{minor}::server""#),
            format!(r#"package:"cpe:/o:redhat:rhel_eus:7.{minor}::computenode""#),
        ]
    })
}

fn rhel8_variants() -> impl Iterator<Item = String> {
    (0..10).into_iter().flat_map(|minor| {
        vec![
            format!(r#"package:"cpe:/o:redhat:rhel_eus:8.{minor}::baseos""#),
            format!(r#"package:"cpe:/a:redhat:rhel_eus:8.{minor}::crb""#),
        ]
    })
}

fn ocp4_variants() -> impl Iterator<Item = String> {
    (0..16)
        .into_iter()
        .flat_map(|minor| vec![format!(r#"package:"cpe:/a:redhat:openshift:4.{minor}::el8""#)])
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn empty() {
        let s = or_group(vec![]).join(" ");
        assert_eq!(s, "");
    }

    #[test]
    fn one() {
        let s = or_group(vec!["a".to_string()]).join(" ");
        assert_eq!(s, "( a )");
    }

    #[test]
    fn three() {
        let s = or_group(vec!["a".to_string(), "b".to_string(), "c".to_string()]).join(" ");
        assert_eq!(s, "( a OR b OR c )");
    }
}
