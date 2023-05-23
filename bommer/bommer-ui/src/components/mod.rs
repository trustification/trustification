//! Re-usable component

pub mod backend;
pub mod workload;

use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_more_hooks::prelude::UseAsyncState;

#[function_component(ExtLinkIcon)]
pub fn ext_link_icon() -> Html {
    html!(<span class="pf-u-icon-color-light pf-u-ml-sm pf-u-font-size-sm">{ Icon::ExternalLinkAlt }</span>)
}

#[function_component(Trusted)]
pub fn trusted() -> Html {
    html!(<Label color={Color::Gold} label="Trusted"/>)
}

pub fn remote_content<T, E, FB>(fetch: &UseAsyncState<T, E>, body: FB) -> Html
where
    FB: FnOnce(&T) -> Html,
    E: std::error::Error,
{
    match &*fetch {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(<Spinner/>),
        UseAsyncState::Ready(Ok(data)) => body(data),
        UseAsyncState::Ready(Err(err)) => html!(<>{"Failed to load: "} { err } </>),
    }
}
