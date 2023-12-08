use crate::analytics::{ActionAnalytics, AnalyticEvents, ObjectNameAnalytics};
use patternfly_yew::prelude::*;
use popper_rs::{
    prelude::{State, *},
    yew::component::{PopperProperties, PortalToPopper},
};
use serde_json::json;
use spog_model::prelude::{Action, Suggestion};
use spog_ui_backend::{use_backend, SuggestionService};
use spog_ui_common::components::SafeHtml;
use spog_ui_common::error::ApiError;
use spog_ui_navigation::{AppRoute, View};
use spog_ui_utils::{analytics::use_analytics, config::use_config};
use wasm_bindgen::JsCast;
use yew::prelude::*;
use yew_hooks::{use_click_away, use_debounce_state, use_event_with_window};
use yew_more_hooks::hooks::use_async_with_cloned_deps;
use yew_more_hooks::prelude::UseAsyncState;
use yew_nested_router::prelude::*;
use yew_oauth2::hook::use_latest_access_token;

#[function_component(Index)]
pub fn index() -> Html {
    let config = use_config();
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
                                        <GridItem offset={[2]} cols={[4]}>
                                            <Search {onchange} />
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

                    <SafeHtml html={config.landing_page.after_outer_content.clone()} />

                </Grid>

            </PageSection>

            <SafeHtml html={config.landing_page.footer_content.clone()} />

        </>
    )
}

#[derive(PartialEq, Properties)]
struct SearchProperties {
    onchange: Callback<String>,
}

#[function_component(Search)]
fn search(props: &SearchProperties) -> Html {
    const ID_SEARCH_ELEMENT: &str = "search_terms";

    let backend = use_backend();
    let access_token = use_latest_access_token();
    let analytics = use_analytics();

    // references to nodes
    let away_ref = use_node_ref();
    let input_ref = use_node_ref();
    let menu_ref = use_node_ref();

    // the search term
    let value = use_state_eq(String::new);

    // debounced value
    let debounced_value = use_debounce_state(String::new, 250);

    // the values filtered by the search value
    let possible_values = use_state_eq(Vec::<Suggestion>::default);

    // clear the value
    let onclear = use_callback(value.setter(), |_, value| value.set(String::new()));

    // popper state
    let state = use_state_eq(State::default);
    let onstatechange = use_callback(state.clone(), |new_state, state| state.set(new_state));

    // the state of the auto complete menu
    let autocomplete_open = use_state_eq(|| false);
    let autocomplete_loading = use_state_eq(|| false);

    // consume the changes from the input
    let onchange = use_callback(value.setter(), |value, setter| setter.set(value));

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
    let suggestions = use_async_with_cloned_deps(
        |value| async move {
            if value.is_empty() {
                return Ok::<_, ApiError>(vec![]);
            }

            let result = SuggestionService::new(backend, access_token).search(&value).await?;

            analytics.track((
                "Search Suggestions",
                json!({
                    "in": value,
                    "out": result,
                }),
            ));

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
                "Escape" => {
                    // escape should always close the menu
                    autocomplete_open.set(false);
                    // focus back on the input control
                    input_ref.focus();
                }
                _ => {}
            }
        });
    }

    // the autocomplete menu
    let autocomplete = html!(<SuggestionMenu
        r#ref={menu_ref.clone()}
        state={(*state).clone()}
        possible_values={(*possible_values).clone()}
        loading={*autocomplete_loading}
    />);

    {
        // only when the value changes, emit the callback
        let onchange = props.onchange.clone();
        use_effect_with((*value).clone(), move |value| {
            onchange.emit(value.clone());
        });
    }

    html!(
        <div ref={away_ref}>
            <SearchInput
                id={ID_SEARCH_ELEMENT}
                inner_ref={input_ref.clone()}
                placeholder="Search for an SBOM, advisory, or CVE"
                value={(*value).clone()}
                {onchange}
                {onclear}
                autofocus=true
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
                append_to={gloo_utils::document().get_element_by_id(ID_SEARCH_ELEMENT)}
            >
                { autocomplete }
            </PortalToPopper>

        </div>
    )
}

#[derive(PartialEq, Properties)]
struct SuggestionMenuProperties {
    r#ref: NodeRef,
    possible_values: Vec<Suggestion>,
    state: State,
    loading: bool,
}

#[function_component(SuggestionMenu)]
fn suggestion_menu(props: &SuggestionMenuProperties) -> Html {
    let router = use_router::<AppRoute>().expect("Must be nested under the AppRoute router");

    html!(
        <Menu
            r#ref={props.r#ref.clone()}
            style={&props.state
                .styles.popper
                .extend_with("z-index", "1000")
            }
        >
            { for props.possible_values.clone().into_iter().map(| Suggestion { label, description, action } : Suggestion | {
                let router = router.clone();
                let onclick = Callback::from(move |_| {
                    match &action {
                        Action::Cve(id) => {
                            router.push(AppRoute::Cve(View::Content{id: id.clone()}));
                        },
                    }
                });

                let description = description.as_ref().map(|s|s.to_string());
                html_nested!(
                    <MenuAction {onclick} {description}>{ label }</MenuAction>
                )
            })}
            { for props.loading.then(|| html_nested!(<MenuLoading />)) }
        </Menu>
    )
}
