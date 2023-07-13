use crate::pages::AppRoute;
use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_nested_router::prelude::use_router;

#[function_component(NotFound)]
pub fn not_found() -> Html {
    let router = use_router();

    let onhome = {
        Callback::from(move |_| {
            if let Some(router) = &router {
                router.push(AppRoute::Index);
            }
        })
    };

    html!(
        <Bullseye>
            <EmptyState
                title="404 – Page not found"
                size={Size::XXXLarge}
                primary={Action::new("Take me home", onhome)}
            >
            </EmptyState>
        </Bullseye>
    )
}
