use patternfly_yew::prelude::*;
use serde_json::json;
use spog_ui_backend::ApplyAccessToken;
use spog_ui_utils::analytics::use_wrap_tracking;
use std::rc::Rc;
use url::Url;
use wasm_bindgen::JsValue;
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

    let onclick = use_callback(props.href.clone(), move |_, href| {
        let href = href.clone().latest_access_token(&access_token);
        let _ = gloo_utils::window().location().set_href(href.as_str());
    });

    let onclick = use_wrap_tracking(onclick, props.href.clone(), |_, href| {
        ("Download File", json!({"href": href}))
    });

    html!(
        <Button
            icon={Icon::Download}
            variant={ButtonVariant::Plain}
            {onclick}
        />
    )
}

#[derive(PartialEq, Properties)]
pub struct LocalDownloadButtonProperties {
    pub data: Rc<String>,

    pub r#type: String,
    pub filename: String,
}

/// "Download" from an already loaded set of data
#[function_component(LocalDownloadButton)]
pub fn inline_download(props: &LocalDownloadButtonProperties) -> Html {
    let onclick = use_callback((), move |_, ()| {});

    let onclick = use_wrap_tracking(
        onclick,
        (props.r#type.clone(), props.filename.clone()),
        |_, (r#type, filename)| ("Download File", json!({"type": r#type, "filename": filename})),
    );

    let href = use_state_eq::<Option<String>, _>(|| None);

    use_effect_with((props.data.clone(), href.setter()), |(data, href)| {
        let url = web_sys::Blob::new_with_str_sequence(&js_sys::Array::of1(&JsValue::from_str(data)))
            .and_then(|blob| web_sys::Url::create_object_url_with_blob(&blob))
            .ok();

        log::debug!("Created object URL: {url:?}");

        href.set(url.clone());

        move || {
            log::debug!("Dropping object URL: {url:?}");
            if let Some(url) = url {
                let _ = web_sys::Url::revoke_object_url(&url);
            }
        }
    });

    html!(
        if let Some(href) = (*href).clone() {
            <a download={props.filename.clone()} class="pf-v5-c-button pf-m-secondary" {href} {onclick}>
                <span class="pf-v5-c-button__icon pf-m-start">
                    { Icon::Download }
                </span>
                { "Download" }
            </a>
        }
    )
}
