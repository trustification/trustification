use patternfly_yew::prelude::*;
use popper_rs::{
    prelude::{State, *},
    yew::component::{PopperProperties, PortalToPopper},
};
use serde_json::json;
use spog_model::prelude::{Action, Suggestion};
use spog_ui_backend::{use_backend, SuggestionService};
use spog_ui_common::error::ApiError;
use spog_ui_navigation::{AppRoute, View};
use spog_ui_utils::analytics::use_analytics;
use std::ops::Deref;
use wasm_bindgen::JsCast;
use web_tools::prelude::*;
use yew::prelude::*;
use yew_hooks::{use_click_away, use_debounce_state, use_event_with_window};
use yew_more_hooks::{hooks::use_async_with_cloned_deps, prelude::UseAsyncState};
use yew_nested_router::prelude::*;
use yew_oauth2::hook::use_latest_access_token;

#[derive(PartialEq, Properties)]
pub struct SearchProperties {
    pub onchange: Callback<String>,

    #[prop_or_default]
    pub autofocus: bool,

    #[prop_or_default]
    pub submit_on_enter: bool,

    #[prop_or_default]
    pub initial_value: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Initialized<T> {
    Initial(T),
    Modified(T),
}

impl<T> Initialized<T> {
    pub fn is_initial(&self) -> bool {
        matches!(self, Self::Initial(_))
    }
}

impl<T> From<T> for Initialized<T> {
    fn from(value: T) -> Self {
        Self::Modified(value)
    }
}

impl<T> Deref for Initialized<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Initial(value) => value,
            Self::Modified(value) => value,
        }
    }
}

#[function_component(SearchInput)]
pub fn search_input(props: &SearchProperties) -> Html {
    const ID_SEARCH_ELEMENT: &str = "search_terms";

    let backend = use_backend();
    let access_token = use_latest_access_token();
    let analytics = use_analytics();

    // references to nodes
    let away_ref = use_node_ref();
    let input_ref = use_node_ref();
    let menu_ref = use_node_ref();

    // the search term
    let value = use_state_eq(|| Initialized::Initial(props.initial_value.clone().unwrap_or_default()));

    // debounced value
    let debounced_value = use_debounce_state(|| (*value).clone(), 250);

    // the values filtered by the search value
    let possible_values = use_state_eq(Vec::<Suggestion>::default);

    // clear the value
    let onclear = use_callback(
        (value.setter(), props.submit_on_enter, input_ref.clone()),
        |_, (value, submit_on_enter, input_ref)| {
            value.set(String::new().into());

            if *submit_on_enter {
                input_ref.form().submit();
            }
        },
    );

    // popper state
    let state = use_state_eq(State::default);
    let onstatechange = use_callback(state.clone(), |new_state, state| state.set(new_state));

    // the state of the auto complete menu
    let autocomplete_open = use_state_eq(|| false);
    let autocomplete_loading = use_state_eq(|| false);

    // consume the changes from the input
    let onchange = use_callback(value.setter(), |value: String, setter| setter.set(value.into()));

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
            if value.is_initial() {
                return Ok::<_, ApiError>(vec![]);
            }

            let result = SuggestionService::new(backend, access_token).search(&value).await?;

            analytics.track((
                "Search Suggestions",
                json!({
                    "in": value.deref(),
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
            onchange.emit((**value).clone());
        });
    }

    html!(
        <div ref={away_ref}>
            <patternfly_yew::prelude::SearchInput
                id={ID_SEARCH_ELEMENT}
                inner_ref={input_ref.clone()}
                placeholder="Search for an SBOM, advisory, or CVE"
                value={(**value).clone()}
                {onchange}
                {onclear}
                autofocus={props.autofocus}
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

                let r#type = match &action {
                    Action::Cve{ advisory: false, .. } => html!(<Label color={Color::Orange} compact=true label="CVE" />),
                    Action::Cve{ advisory: true, .. } => html!(<>
                        <Label color={Color::Orange} compact=true label="CVE" />
                        {" "}
                        <Label color={Color::Blue} compact=true label="Advisory" />
                    </>),
                    Action::Advisory(_) => html!(<Label color={Color::Blue} compact=true label="Advisory" />),
                    Action::Sbom(_) => html!(<Label color={Color::Purple} compact=true label="SBOM" />),
                };

                let onclick = Callback::from(move |_| {
                    match &action {
                        Action::Cve{id, ..} => {
                            router.push(AppRoute::Cve(View::Content{id: id.clone()}));
                        },
                        Action::Advisory(id) => {
                            router.push(AppRoute::Advisory(View::Content{id: id.clone()}));
                        }
                        Action::Sbom(id) => {
                            router.push(AppRoute::Sbom(View::Content{id: id.clone()}));
                        }
                    }
                });

                let description = description.as_ref().map(|s|s.to_string());

                html_nested!(
                    <MenuAction
                        {onclick}
                    >
                        <Stack>
                            <StackItem>
                                <Split gutter=true>
                                    <SplitItem>{ label }</SplitItem>
                                    <SplitItem>{ r#type }</SplitItem>
                                </Split>
                            </StackItem>
                            <StackItem>
                                <span class="pf-v5-u-font-size-xs pf-v5-u-color-200">
                                    { description }
                                </span>
                            </StackItem>
                        </Stack>
                    </MenuAction>
                )
            })}
            { for props.loading.then(|| html_nested!(<MenuLoading />)) }
        </Menu>
    )
}
