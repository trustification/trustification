//! Re-usable component

pub mod advisory;
pub mod async_state_renderer;
pub mod backend;
pub mod common;
pub mod content;
pub mod cve;
pub mod cvss;
pub mod download;
pub mod editor;
pub mod hooks;
pub mod markdown;
pub mod pagination;
pub mod sbom;
pub mod search;
pub mod severity;
pub mod spdx;
pub mod table_wrapper;
pub mod theme;
pub mod time;

use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(ExtLinkIcon)]
pub fn ext_link_icon() -> Html {
    html!(<span class="pf-u-icon-color-light pf-u-ml-sm pf-u-font-size-sm">{ Icon::ExternalLinkAlt }</span>)
}

#[function_component(Trusted)]
pub fn trusted() -> Html {
    html!(<Label color={Color::Gold} label="Trusted"/>)
}
