use crate::backend::ApplyAccessToken;
use patternfly_yew::prelude::*;
use url::Url;
use yew::prelude::*;
use yew_oauth2::hook::use_latest_access_token;

#[derive(PartialEq, Properties)]
pub struct DownloadProperties {
    #[prop_or_default]
    pub children: Children,

    pub href: Url,
}

#[function_component(Download)]
pub fn download(props: &DownloadProperties) -> Html {
    let access_token = use_latest_access_token();

    let onclick = use_callback(
        move |_, href| {
            let href = href.clone().latest_access_token(&access_token);
            let _ = gloo_utils::window().location().set_href(href.as_str());
        },
        props.href.clone(),
    );
    html!(
        <Button
            icon={Icon::Download}
            variant={ButtonVariant::Plain}
            {onclick}
        />
    )
}
