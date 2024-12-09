use patternfly_yew::prelude::*;
use serde_json::json;
use spog_ui_backend::{use_backend, ApplyAccessToken};
use spog_ui_utils::analytics::use_wrap_tracking;
use std::rc::Rc;
use url::Url;
use wasm_bindgen::{JsCast, JsValue};
use yew::prelude::*;
use yew_oauth2::hook::use_latest_access_token;

#[derive(PartialEq, Clone)]
pub enum SbomSource {
    URL(Option<Url>),

    // Data, filename
    LOCAL(Rc<String>, String),
}

#[derive(PartialEq, Properties)]
pub struct SbomKebabDropdownProperties {
    pub id: String,
    pub sbom_source: SbomSource,

    #[prop_or_default]
    pub dropdown_text: Option<String>,

    #[prop_or_default]
    pub dropdown_icon: Option<Html>,

    #[prop_or_default]
    pub dropdown_variant: MenuToggleVariant,
}

#[function_component(SbomKebabDropdown)]
pub fn sbom_kebab_dropdown(props: &SbomKebabDropdownProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let local_file = use_state_eq(|| None);

    let on_download_sbom_click = use_callback((props.sbom_source.clone(), access_token.clone()), {
        let local_file = local_file.clone();
        move |_, (sbom_source, access_token)| match sbom_source {
            SbomSource::URL(href) => {
                if let Some(href) = href {
                    let href = href.clone().latest_access_token(access_token);
                    let _ = gloo_utils::window().location().set_href(href.as_str());
                }
            }
            SbomSource::LOCAL(data, filename) => {
                local_file.set(Some((data.clone(), filename.clone())));
            }
        }
    });

    let on_download_licenses_click = use_callback(
        (props.id.clone(), access_token.clone()),
        move |_, (id, access_token)| {
            if let Ok(href) = backend.join(spog_ui_backend::Endpoint::Api, &format!("/api/v1/sbom/license/{}", id)) {
                let href = href.clone().latest_access_token(access_token);
                let _ = gloo_utils::window().location().set_href(href.as_str());
            };
        },
    );

    use_effect_with(local_file.clone(), |local_file| {
        if let Some((data, filename)) = (*local_file.clone()).clone() {
            let url = web_sys::Blob::new_with_str_sequence(&js_sys::Array::of1(&JsValue::from_str(&data)))
                .and_then(|blob| web_sys::Url::create_object_url_with_blob(&blob))
                .ok();
            if let Some(url) = url {
                let document = gloo_utils::window()
                    .document()
                    .expect("Not able to create gloo_utils::window().document()");
                let anchor = document
                    .create_element("a")
                    .expect("Not able to create '<a/>' ")
                    .dyn_into::<web_sys::HtmlElement>()
                    .expect("Not able to dyn_into HtmlElement");

                let _ = anchor.set_attribute("href", &url);
                let _ = anchor.set_attribute("download", &filename);
                document
                    .body()
                    .expect("Not able to pick document.body()")
                    .append_child(&anchor)
                    .expect("Not able to attach fake <a/>");
                anchor.click();

                let _ = web_sys::Url::revoke_object_url(&url);
            }
        }
    });

    html!(
        <Dropdown
                text={props.dropdown_text.clone()}
                variant={props.dropdown_variant}
                icon={props.dropdown_icon.clone()}
        >
            <MenuAction onclick={on_download_sbom_click}>{"Download SBOM"}</MenuAction>
            <MenuAction onclick={on_download_licenses_click}>{"Download License Report"}</MenuAction>
        </Dropdown>
    )
}

#[derive(PartialEq, Properties)]
pub struct DownloadProperties {
    #[prop_or_default]
    pub children: Children,

    pub href: Url,
    pub r#type: String,
}

#[function_component(Download)]
pub fn download(props: &DownloadProperties) -> Html {
    let access_token = use_latest_access_token();

    let onclick = use_callback(props.href.clone(), move |_, href| {
        let href = href.clone().latest_access_token(&access_token);
        let _ = gloo_utils::window().location().set_href(href.as_str());
    });

    let onclick = use_wrap_tracking(
        onclick,
        (props.r#type.clone(), props.href.clone()),
        |_, (r#type, href)| ("SearchPage File Downloaded", json!({"type": r#type, "href": href})),
    );

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
        |_, (r#type, filename)| {
            (
                "DetailsPage File Downloaded",
                json!({"type": r#type, "filename": filename}),
            )
        },
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
