use patternfly_yew::prelude::*;
use spog_ui_navigation::AppRoute;
use yew::prelude::*;
use yew_nested_router::prelude::use_router;

#[function_component(NotLoggedIn)]
pub fn not_logged_in() -> Html {
    let router = use_router();

    let onhome = use_callback(
        |_, router| {
            if let Some(router) = &router {
                router.push(AppRoute::Index);
            }
        },
        router,
    );

    html!(
        <Bullseye>
            <EmptyState
                title="Login required"
                size={Size::XXXLarge}
                primary={Action::new("Let me in", onhome)}
            >
            </EmptyState>
        </Bullseye>
    )
}
