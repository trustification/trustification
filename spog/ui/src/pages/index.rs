use std::rc::Rc;

use crate::pages::sbom_report::as_float;
use crate::pages::sbom_report::donut_options;
use crate::{
    analytics::{ActionAnalytics, AnalyticEvents, ObjectNameAnalytics},
    pages::search,
};
use futures::TryFutureExt;
use gloo_events::EventListener;
use patternfly_yew::prelude::*;
use popper_rs::{
    prelude::{State, *},
    yew::component::{PopperProperties, PortalToPopper},
};
use search::search_input::SearchInput;
use serde_json::Value;
use spog_model::prelude::Preferences;
use spog_model::search::SbomSummary;
use spog_ui_backend::SearchParameters;
use spog_ui_backend::{use_backend, DashboardService, PackageService, SBOMService};
use spog_ui_common::{
    components::SafeHtml,
    error::{components::Error, ApiError},
    utils::time::full_utc_date,
};
use spog_ui_components::common::NotFound;
use spog_ui_donut::{Donut, SbomStackChart};
use spog_ui_navigation::{AppRoute, View};
use spog_ui_utils::{analytics::use_analytics, config::use_config_private};
use trustification_api::search::SearchOptions;
use wasm_bindgen::JsCast;
use web_sys::HtmlElement;
use yew::prelude::*;
use yew_hooks::{use_click_away, use_debounce_state, use_event_with_window};
use yew_more_hooks::prelude::*;
use yew_nested_router::components::Link;
use yew_nested_router::prelude::*;
use yew_oauth2::hook::use_latest_access_token;

#[function_component(Index)]
pub fn index() -> Html {
    let config = use_config_private();
    let analytics = use_analytics();

    let text = use_state_eq(String::new);
    let onchange = use_callback(text.clone(), |new_text, text| text.set(new_text));

    let router = use_router::<AppRoute>();
    let onclick = use_callback((router.clone(), text.clone()), |_, (router, terms)| {
        if let Some(router) = router {
            router.push(AppRoute::Search {
                terms: (**terms).clone(),
            });
        }
    });
    let onsubmit = use_callback(
        (analytics.clone(), router.clone(), text.clone()),
        |_, (analytics, router, terms)| {
            analytics.track(AnalyticEvents {
                obj_name: ObjectNameAnalytics::HomePage,
                action: ActionAnalytics::Search((**terms).clone()),
            });

            if let Some(router) = router {
                router.push(AppRoute::Search {
                    terms: (**terms).clone(),
                });
            }
        },
    );

    html!(
        <>
            <SafeHtml html={config.landing_page.header_content.clone()} />

            <PageSection variant={PageSectionVariant::Default}>

                <Grid gutter=true>

                    <SafeHtml html={config.landing_page.before_outer_content.clone()} />

                    <GridItem cols={[12]}>
                        <Card>
                            <CardBody>
                                <SafeHtml html={config.landing_page.before_inner_content.clone()} />

                                <form {onsubmit}>
                                    // needed to trigger submit when pressing enter in the search field
                                    <input type="submit" hidden=true formmethod="dialog" />

                                    <Grid gutter=true>
                                        <GridItem cols={[4]}>
                                            <SearchInput {onchange} autofocus=true />
                                        </GridItem>

                                        <GridItem cols={[1]}>
                                            <Button
                                                id="search"
                                                variant={ButtonVariant::Primary}
                                                label="Search"
                                                {onclick}
                                            />
                                        </GridItem>
                                    </Grid>

                                </form>
                                <SafeHtml html={config.landing_page.after_inner_content.clone()} />

                            </CardBody>
                        </Card>
                    </GridItem>

                    <GridItem cols={[12]}>
                        <Card>
                            <CardTitle><Title size={Size::Medium}>{"Your dashboard"}</Title></CardTitle>
                            <CardBody>
                                <Grid gutter=true>
                                    <GridItem cols={[6]}>
                                        <Stack gutter=true>
                                            <StackItem>
                                                {"Below is a summary of CVE status for your last 10 ingested SBOMs. You can click on the SBOM name or CVE severity number below to be taken to their respective details page. You can also select up to 4 SBOMs to watch, by default you will see the last 4 SBOMs you have uploaded."}
                                            </StackItem>
                                            <StackItem>
                                                <div class="pf-v5-l-split">
                                                    <LastSbomsChart />
                                                </div>
                                            </StackItem>
                                        </Stack>
                                    </GridItem>
                                    <GridItem cols={[6]}>
                                        <LastDataIngested />
                                    </GridItem>
                                </Grid>
                            </CardBody>
                        </Card>
                    </GridItem>

                    <GridItem cols={[12]}>
                        <SelectedSbomsByUser />
                    </GridItem>

                    <SafeHtml html={config.landing_page.after_outer_content.clone()} />

                </Grid>

            </PageSection>

            <SafeHtml html={config.landing_page.footer_content.clone()} />

        </>
    )
}

#[function_component(LastSbomsChart)]
pub fn last_sboms_chart() -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let sboms = use_async_with_cloned_deps(
        |backend| async move {
            SBOMService::new(backend.clone(), access_token)
                .get_latest_with_vulns()
                .await
                .map(|result| {
                    let number_of_elements = result.len();
                    let json = serde_json::to_value(result).expect("Could not unparse latest sbom json");
                    (json, number_of_elements)
                })
        },
        backend,
    );

    html!(
        <>
            {
                match &*sboms {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        </PageSection>
                    ),
                    UseAsyncState::Ready(Ok((json, number_of_elements))) => html!(
                        if *number_of_elements > 0usize {
                            <SbomStackChart sboms={json.clone()} style="height: 375px; width: 750px" />
                        } else {
                            <EmptyState
                                title="No SBOMs found"
                                icon={Icon::Cubes}
                            >
                            </EmptyState>
                        }
                    ),
                    UseAsyncState::Ready(Err(_)) => html!(
                        <Error title="Error" message="Internal server error" />
                    ),
                }
            }
        </>
    )
}

#[function_component(LastDataIngested)]
pub fn last_data_ingested() -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let summary = use_async_with_cloned_deps(
        |backend| async move {
            DashboardService::new(backend.clone(), access_token)
                .get_summary()
                .await
                .map(Rc::new)
        },
        backend,
    );

    html!(
        <>
            {
                match &*summary {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        </PageSection>
                    ),
                    UseAsyncState::Ready(Ok(value)) => html!(
                        <Grid gutter=true>
                            <GridItem cols={[6]}>
                                <DescriptionList>
                                    <DescriptionGroup term="Last SBOM ingested">
                                        <Stack>
                                            <StackItem>
                                                if let Some(last_updated_date) = &value.sbom_summary.last_updated_date {
                                                    {full_utc_date(*last_updated_date)}
                                                }
                                            </StackItem>
                                            <StackItem>
                                                if let Some(last_updated_sbom_id) = &value.sbom_summary.last_updated_sbom_id {
                                                    <Link<AppRoute> to={AppRoute::Sbom(View::Content {id: last_updated_sbom_id.clone()})} >
                                                        { &value.sbom_summary.last_updated_sbom_name }
                                                    </Link<AppRoute>>
                                                }
                                            </StackItem>
                                        </Stack>
                                    </DescriptionGroup>
                                </DescriptionList>
                            </GridItem>
                            <GridItem cols={[6]}>
                                <DescriptionList>
                                    <DescriptionGroup term="Total SBOMs">
                                        {value.sbom_summary.total_sboms}
                                    </DescriptionGroup>
                                </DescriptionList>
                            </GridItem>

                            <GridItem cols={[6]}>
                                <DescriptionList>
                                    <DescriptionGroup term="Last Advisory ingested">
                                        <Stack>
                                            <StackItem>
                                                if let Some(last_updated_date) = &value.csaf_summary.last_updated_date {
                                                    {full_utc_date(*last_updated_date)}
                                                }
                                            </StackItem>
                                            <StackItem>
                                                if let Some(last_updated_csaf_id) = &value.csaf_summary.last_updated_csaf_id {
                                                    <Link<AppRoute> to={AppRoute::Advisory(View::Content {id: last_updated_csaf_id.clone()})} >
                                                        { &value.csaf_summary.last_updated_csaf_id }
                                                    </Link<AppRoute>>
                                                }
                                            </StackItem>
                                        </Stack>
                                    </DescriptionGroup>
                                </DescriptionList>
                            </GridItem>
                            <GridItem cols={[6]}>
                                <DescriptionList>
                                    <DescriptionGroup term="Total Advisories">
                                        {value.csaf_summary.total_csafs}
                                    </DescriptionGroup>
                                </DescriptionList>
                            </GridItem>

                            <GridItem cols={[6]}>
                                <DescriptionList>
                                    <DescriptionGroup term="Last CVE ingested">
                                        <Stack>
                                            <StackItem>
                                                if let Some(last_updated_date) = &value.cve_summary.last_updated_date {
                                                    {full_utc_date(*last_updated_date)}
                                                }
                                            </StackItem>
                                            <StackItem>
                                                if let Some(last_updated_cve) = &value.cve_summary.last_updated_cve {
                                                    <Link<AppRoute> to={AppRoute::Cve(View::Content {id: last_updated_cve.clone()})} >
                                                        { &value.cve_summary.last_updated_cve }
                                                    </Link<AppRoute>>
                                                }
                                            </StackItem>
                                        </Stack>
                                    </DescriptionGroup>
                                </DescriptionList>
                            </GridItem>
                            <GridItem cols={[6]}>
                                <DescriptionList>
                                    <DescriptionGroup term="Total CVEs">
                                        {value.cve_summary.total_cves}
                                    </DescriptionGroup>
                                </DescriptionList>
                            </GridItem>
                        </Grid>
                    ),
                    UseAsyncState::Ready(Err(_)) => html!(
                        <Error title="Error" message="Error while uploading the file" />
                    ),
                }
            }
        </>
    )
}

#[function_component(SelectedSbomsByUser)]
pub fn selected_sboms_by_user() -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let summary = use_async_with_cloned_deps(
        |backend| async move {
            DashboardService::new(backend.clone(), access_token)
                .get_user_preferences()
                .await
                .map(Rc::new)
        },
        backend,
    );

    html!(
        <>
            {
                match &*summary {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        </PageSection>
                    ),
                    UseAsyncState::Ready(Ok(value)) => {
                        html!(
                            <Grid gutter=true>
                                <GridItem cols={[3]}>
                                    <WatchedSbom preferences={value.clone()} sbom_index={SbomIndex::Sbom1} />
                                </GridItem>
                                <GridItem cols={[3]}>
                                    <WatchedSbom preferences={value.clone()} sbom_index={SbomIndex::Sbom2} />
                                </GridItem>
                                <GridItem cols={[3]}>
                                    <WatchedSbom preferences={value.clone()} sbom_index={SbomIndex::Sbom3} />
                                </GridItem>
                                <GridItem cols={[3]}>
                                    <WatchedSbom preferences={value.clone()} sbom_index={SbomIndex::Sbom4} />
                                </GridItem>
                            </Grid>
                        )
                    },
                    UseAsyncState::Ready(Err(_)) => html!(
                        <Error title="Error" message="Error while fetching user preferences" />
                    ),
                }
            }
        </>
    )
}

#[derive(Clone, PartialEq, Properties)]
pub struct SbomNameProperties {
    sbom_id: String,
}

#[function_component(SbomName)]
pub fn watched_sbom(props: &SbomNameProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let sbom_index = use_async_with_cloned_deps(
        |(id, backend, access_token)| async move {
            spog_ui_backend::SBOMService::new(backend.clone(), access_token)
                .get_from_index(&id)
                .await
                .map(|search_result| {
                    if search_result.result.len() == 1 {
                        let data = &search_result.result[0];
                        Some(data.clone())
                    } else {
                        None
                    }
                })
        },
        (props.sbom_id.clone(), backend.clone(), access_token.clone()),
    );

    let title = match &*sbom_index {
        UseAsyncState::Ready(Ok(Some(data))) => html!(data.name.clone()),
        _ => html!(props.sbom_id.clone()),
    };

    html!(
        <>
            {title}
        </>
    )
}

#[derive(Clone, PartialEq)]
enum SbomIndex {
    Sbom1,
    Sbom2,
    Sbom3,
    Sbom4,
}

#[derive(Clone, PartialEq, Properties)]
pub struct WatchedSbomProperties {
    preferences: Rc<Preferences>,
    sbom_index: SbomIndex,
}

impl std::fmt::Display for SbomIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            SbomIndex::Sbom1 => write!(f, "sbom1"),
            SbomIndex::Sbom2 => write!(f, "sbom2"),
            SbomIndex::Sbom3 => write!(f, "sbom3"),
            SbomIndex::Sbom4 => write!(f, "sbom4"),
        }
    }
}

#[function_component(WatchedSbom)]
pub fn watched_sbom(props: &WatchedSbomProperties) -> Html {
    let sbom_id = use_memo(
        (props.preferences.clone(), props.sbom_index.clone()),
        |(preferences, sbom_index)| match sbom_index {
            SbomIndex::Sbom1 => preferences.sbom1.clone(),
            SbomIndex::Sbom2 => preferences.sbom2.clone(),
            SbomIndex::Sbom3 => preferences.sbom3.clone(),
            SbomIndex::Sbom4 => preferences.sbom4.clone(),
        },
    );

    let new_sbom_id = use_state_eq(|| None::<Rc<String>>);
    let set_new_sbom_id = use_callback(new_sbom_id.clone(), |new_val, new_sbom_id| {
        new_sbom_id.set(Some(new_val))
    });

    let sbom_index_suffix = format!("{}", props.sbom_index);

    match &*new_sbom_id {
        Some(sbom_id) => {
            html!(<SaveSbom sbom_index={props.sbom_index.clone()} sbom_id={sbom_id.clone()} />)
        }
        None => {
            html!(
                <Card full_height=true>
                    if let Some(sbom_id) = &*sbom_id {
                        <CardTitle>
                            <Title size={Size::Medium}>
                                <SbomName sbom_id={sbom_id.clone()}/>
                            </Title>
                        </CardTitle>
                        <CardBody>
                            <Stack gutter=true>
                                <StackItem>
                                    <SbomDonutChart sbom_id={sbom_id.clone()}/>
                                </StackItem>
                                <StackItem>
                                    <Link<AppRoute> to={AppRoute::Sbom(View::Content {id: sbom_id.clone()})}>
                                        {"View Details"}
                                    </Link<AppRoute>>
                                </StackItem>
                            </Stack>
                        </CardBody>
                        <CardFooter>
                            <SelectWatchedSbom input_text_id_suffix={sbom_index_suffix.clone()} on_sbom_selected={set_new_sbom_id} />
                        </CardFooter>
                    } else {
                        <CardBody>
                            <Stack gutter=true>
                                <StackItem>
                                    <div class="pf-v5-c-empty-state pf-m-xs">
                                        <div class="pf-v5-c-empty-state__content">
                                            <div class="pf-v5-c-empty-state__header">
                                                <div class="pf-v5-c-empty-state__title">
                                                    <h4 class="pf-v5-c-empty-state__title-text">
                                                        {"There is nothing here yet"}
                                                    </h4>
                                                </div>
                                            </div>
                                            <div class="pf-v5-c-empty-state__body">
                                                {"You can get started by uploading an SBOM. Once your SBOMs are uploaded come back to this page to change the SBOMs you would like to track."}
                                            </div>
                                        </div>
                                    </div>
                                </StackItem>
                            </Stack>
                        </CardBody>
                        <CardFooter>
                            <SelectWatchedSbom input_text_id_suffix={sbom_index_suffix.clone()} on_sbom_selected={set_new_sbom_id} />
                        </CardFooter>
                    }
                </Card>
            )
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct SaveSbomProperties {
    sbom_index: SbomIndex,
    sbom_id: Rc<String>,
}

#[function_component(SaveSbom)]
pub fn inspect(props: &SaveSbomProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let saving = {
        use_async_with_cloned_deps(
            move |(sbom_index, sbom_id)| async move {
                let sbom_id = (*sbom_id).clone();

                let service = DashboardService::new(backend, access_token);
                service
                    .get_user_preferences()
                    .and_then(|current_preferences| {
                        let new_preferences = match sbom_index {
                            SbomIndex::Sbom1 => Preferences {
                                sbom1: Some(sbom_id.clone()),
                                sbom2: current_preferences.sbom2.clone(),
                                sbom3: current_preferences.sbom3.clone(),
                                sbom4: current_preferences.sbom4.clone(),
                            },
                            SbomIndex::Sbom2 => Preferences {
                                sbom1: current_preferences.sbom1.clone(),
                                sbom2: Some(sbom_id.clone()),
                                sbom3: current_preferences.sbom3.clone(),
                                sbom4: current_preferences.sbom4.clone(),
                            },
                            SbomIndex::Sbom3 => Preferences {
                                sbom1: current_preferences.sbom1.clone(),
                                sbom2: current_preferences.sbom2.clone(),
                                sbom3: Some(sbom_id.clone()),
                                sbom4: current_preferences.sbom4.clone(),
                            },
                            SbomIndex::Sbom4 => Preferences {
                                sbom1: current_preferences.sbom1.clone(),
                                sbom2: current_preferences.sbom2.clone(),
                                sbom3: current_preferences.sbom3.clone(),
                                sbom4: Some(sbom_id.clone()),
                            },
                        };

                        service.save_user_preferences(new_preferences)
                    })
                    .await
                    .map(Rc::new)
            },
            (props.sbom_index.clone(), props.sbom_id.clone()),
        )
    };

    html!(
        <>
            {
                match &*saving {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        </PageSection>
                    ),
                    UseAsyncState::Ready(Ok(new_preferences)) => html!(
                        <WatchedSbom preferences={new_preferences} sbom_index={props.sbom_index.clone()}/>
                    ),
                    UseAsyncState::Ready(Err(_)) => html!(
                        <Error title="Error" message="Error while saving data" />
                    ),
                }
            }
        </>
    )
}

#[derive(Clone, PartialEq, Properties)]
pub struct SbomDonutChartProperties {
    sbom_id: String,
}

#[function_component(SbomDonutChart)]
pub fn sbom_donut_chart(props: &SbomDonutChartProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let vulnerabilities = use_async_with_cloned_deps(
        |(id, backend)| async move {
            spog_ui_backend::SBOMService::new(backend.clone(), access_token)
                .get_sbom_vulns(id)
                .await
                .map(|r| r.map(Rc::new))
        },
        (props.sbom_id.clone(), backend),
    );

    let empty = vulnerabilities
        .data()
        .and_then(|d| d.as_ref().map(|d| d.summary("mitre").map(|s| s.is_empty())))
        .flatten()
        .unwrap_or(true);

    let labels = use_callback(empty, |value: Value, empty| {
        if *empty {
            return "None".to_string();
        }

        let x = &value["datum"]["x"];
        let y = &value["datum"]["y"];

        match (x.as_str(), as_float(y)) {
            (Some(x), Some(y)) => format!("{x}: {y}"),
            _ => "Unknown".to_string(),
        }
    });

    match &*vulnerabilities {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(
            <>
                <Bullseye><Spinner/></Bullseye>
            </>
        ),
        UseAsyncState::Ready(Ok(None)) => html!(
            <>
                <NotFound/>
            </>
        ),
        UseAsyncState::Ready(Ok(Some(data))) => {
            let options = donut_options(data);
            html!(
                <>
                    <Donut {options} {labels} style="width: 350px;" />
                </>
            )
        }
        UseAsyncState::Ready(Err(err)) => {
            html!(
                <>
                    <spog_ui_common::error::components::ApiError error={err.clone()} message="Error while generating the chart" />
                </>
            )
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct SelectWatchedSbomProperties {
    input_text_id_suffix: String,
    on_sbom_selected: Callback<Rc<String>>,
}

#[function_component(SelectWatchedSbom)]
pub fn select_watched_sbom(props: &SelectWatchedSbomProperties) -> Html {
    let id_search_element = format!("search-input-{}", props.input_text_id_suffix);

    let backend = use_backend();
    let access_token = use_latest_access_token();

    // references to nodes
    let away_ref = use_node_ref();
    let input_ref = use_node_ref();
    let menu_ref = use_node_ref();

    // the search term
    let value = use_state_eq(String::new);

    // debounced value
    let debounced_value = use_debounce_state(|| (*value).clone(), 250);

    // the values filtered by the search value
    let possible_values = use_state_eq(Vec::<SbomSummary>::default);

    // clear the value
    let onclear = use_callback(value.setter(), |_, value| value.set(String::new()));

    // popper state
    let state = use_state_eq(State::default);
    let onstatechange = use_callback(state.clone(), |new_state, state| state.set(new_state));

    // the state of the auto complete menu
    let autocomplete_open = use_state_eq(|| false);
    let autocomplete_loading = use_state_eq(|| false);

    // consume the changes from the input
    let onchange = use_callback(value.setter(), |value: String, setter| setter.set(value));

    // debounce
    {
        let debounce = debounced_value.clone();
        use_effect_with(
            (
                (*value).clone(),
                autocomplete_loading.setter(),
                autocomplete_open.setter(),
            ),
            move |(value, autocomplete_loading, autocomplete_open)| {
                if !value.is_empty() {
                    autocomplete_loading.set(true);
                    autocomplete_open.set(true);
                }

                debounce.set(value.clone());
            },
        );
    }

    // retrieve the suggestions
    let suggestions: UseAsyncHandleDeps<Vec<SbomSummary>, ApiError> = use_async_with_cloned_deps(
        |value| async move {
            let search_parameters = SearchParameters {
                offset: Some(0),
                limit: Some(10),
                options: SearchOptions {
                    explain: false,
                    metadata: true,
                    summaries: true,
                },
            };
            let result = PackageService::new(backend, access_token)
                .search_packages(&value, &search_parameters)
                .await?
                .result;

            Ok(result)
        },
        (*debounced_value).clone(),
    );

    // apply the async outcome to the suggestion menu
    use_effect_with(
        (
            !value.is_empty(),
            autocomplete_open.setter(),
            autocomplete_loading.setter(),
            possible_values.setter(),
            (*suggestions).clone(),
        ),
        |(has_value, autocomplete_open, autocomplete_loading, possible_values, suggestions)| match suggestions {
            UseAsyncState::Processing => {
                autocomplete_loading.set(true);
                autocomplete_open.set(true);
            }
            UseAsyncState::Ready(Ok(data)) => {
                autocomplete_loading.set(false);
                possible_values.set(data.clone());
                if *has_value {
                    autocomplete_open.set(!data.is_empty());
                } else {
                    autocomplete_open.set(false);
                }
            }
            UseAsyncState::Ready(Err(_)) => {
                possible_values.set(vec![]);
                autocomplete_open.set(false);
            }
            _ => {}
        },
    );

    {
        // when the user clicks outside the auto-complete menu, we close it
        let autocomplete_open = autocomplete_open.clone();
        use_click_away(away_ref.clone(), move |_: Event| autocomplete_open.set(false));
    }

    // keyboard handling, on top of the menu
    {
        let autocomplete_open = autocomplete_open.clone();
        let input_ref = input_ref.clone();
        let menu_ref = menu_ref.clone();
        use_event_with_window("keydown", move |e: KeyboardEvent| {
            let in_input = input_ref.get().as_deref() == e.target().as_ref();

            match e.key().as_str() {
                "ArrowUp" | "ArrowDown" if in_input => {
                    // start the menu navigation, the menu component will pick it up from here
                    if let Some(first) = menu_ref
                        .cast::<web_sys::HtmlElement>()
                        .and_then(|ele| ele.query_selector("li > button:not(:disabled)").ok().flatten())
                        .and_then(|ele| ele.dyn_into::<web_sys::HtmlElement>().ok())
                    {
                        let _ = first.focus();
                    }
                    e.prevent_default();
                }
                "Enter" => {
                    // when the user submits the content, close the auto-complete menu
                    autocomplete_open.set(false);
                }
                _ => {}
            }
        });
    }

    // the autocomplete menu
    let autocomplete = {
        let value_setter = value.setter();
        let autocomplete_open = autocomplete_open.setter();
        html!(
            <Menu
                r#ref={menu_ref.clone()}
                style={&state
                    .styles.popper
                    // .extend_with("z-index", "1000")
                }
            >
                { for possible_values.iter().map(|sbom| {
                    let onclick = {
                        let on_sbom_selected = props.on_sbom_selected.clone();

                        let value_setter = value_setter.clone();
                        let sbom_id = sbom.id.to_string();
                        let sbom_name = sbom.name.to_string();
                        let autocomplete_open = autocomplete_open.clone();
                        // let input_ref = input_ref.clone();
                        Callback::from(move |_| {
                            on_sbom_selected.emit(Rc::new(sbom_id.clone()));
                            value_setter.set(sbom_name.clone());
                            autocomplete_open.set(false);
                            // input_ref.focus();
                        })
                    };
                    html_nested!(
                        <MenuAction {onclick}>{ &sbom.name }</MenuAction>
                    )
                })}
                { for autocomplete_loading.then(|| html_nested!(<MenuLoading />)) }
            </Menu>
        )
    };

    // on input focus
    use_effect_with(input_ref.clone(), {
        let input_ref = input_ref.clone();
        let autocomplete_open = autocomplete_open.clone();
        move |_| {
            let mut listener = None;
            if let Some(element) = input_ref.cast::<HtmlElement>() {
                let on_event = Callback::from(move |_: Event| {
                    autocomplete_open.set(true);
                });
                let event_listener = EventListener::new(&element, "focus", move |e| on_event.emit(e.clone()));

                listener = Some(event_listener);
            }
            move || drop(listener)
        }
    });

    // on angle down button click
    let on_angle_down_button_click = use_callback(
        (autocomplete_open.clone(), input_ref.clone()),
        |_, (autocomplete_open, input_ref)| {
            autocomplete_open.set(true);
            input_ref.focus();
        },
    );

    html!(
        <>
            <TextInputGroup class="dashboard-select-sbom">
                <div ref={away_ref}>
                    <patternfly_yew::prelude::SearchInput
                        id={id_search_element.clone()}
                        inner_ref={input_ref.clone()}
                        placeholder="Select a new SBOM to watch"
                        value={(*value).clone()}
                        {onchange}
                        {onclear}
                    />
                    <PortalToPopper
                        popper={yew::props!(PopperProperties {
                            target: input_ref.clone(),
                            content: menu_ref.clone(),
                            placement: Placement::Bottom,
                            visible: *autocomplete_open,
                            modifiers: vec![
                                Modifier::SameWidth(Default::default()),
                            ],
                            onstatechange
                        })}
                        append_to={gloo_utils::document().get_element_by_id(&id_search_element)}
                    >
                        { autocomplete }
                    </PortalToPopper>
                </div>
                <TextInputGroupUtilities>
                    <Button
                        icon={Icon::AngleDown}
                        variant={ButtonVariant::Control}
                        onclick={on_angle_down_button_click}
                    />
                </TextInputGroupUtilities>
            </TextInputGroup>
        </>
    )
}
