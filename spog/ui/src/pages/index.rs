use crate::hooks::use_config;
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(Index)]
pub fn index() -> Html {
    let config = use_config();

    html!(
        <>
            { Html::from_html_unchecked(config.landing_page.content.clone().into()) }
        </>
    )
}
