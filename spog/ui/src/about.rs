use patternfly_yew::prelude::*;
use spog_ui_backend::{use_backend, VersionService};
use spog_ui_common::config::use_config_public;
use std::rc::Rc;
use trustification_version::{version, VersionInformation};
use yew::prelude::*;
use yew_more_hooks::hooks::*;
use yew_oauth2::hook::use_latest_access_token;

#[function_component(About)]
pub fn about() -> Html {
    let config = use_config_public();
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let _version = use_memo((), |()| version!());

    let _remote = use_async_with_cloned_deps(
        |backend| async {
            VersionService::new(backend, access_token)
                .get_version()
                .await
                .map(Rc::new)
        },
        backend.clone(),
    );

    let brand_image_src = config.global.about_brand_image_src();
    let background_image_src = config.global.about_background_src();
    let product_name = config.global.product_name();

    html!(
        <Bullseye plain=true>
            <AboutModal
                {brand_image_src}
                brand_image_alt="Brand Logo"
                {background_image_src}
                {product_name}
                trademark="Copyright © 2020, 2024 Red Hat, Inc"
                class="rhtpa-about"
            >
                <div class="pf-v5-c-content pf-v5-u-py-xl">
                    <h1>{"About"}</h1>
                    <p>{"Red Hat’s Trusted Profile Analyzer (RHTPA) is a proactive service that assists in risk management of Open Source Software (OSS) packages and dependencies. The Trusted Profile Analyzer service brings awareness to and remediation of OSS vulnerabilities discovered within the software supply chain."}</p>
                </div>
                <div class="pf-v5-c-content pf-v5-u-py-xl">
                    <dl>
                        <dt>{"Version"}</dt>
                        <dd>
                            {"1.3.0"}
                        </dd>
                    </dl>
                </div>
            </AboutModal>
        </Bullseye>
    )
}

#[derive(PartialEq, Properties)]
pub struct VersionInfoProperties {
    pub version: Rc<VersionInformation>,
}

#[function_component(VersionInfo)]
fn version_info(props: &VersionInfoProperties) -> Html {
    html!(
        <dl>
            <dt>{ "Version" }</dt>
            <dd>{ &props.version.version }</dd>
            if let Some(info) = &props.version.git.describe {
                <dt>{ "Git" }</dt>
                <dd>{ &info }</dd>
            }
            <dt>{ "Build timestamp" }</dt>
            <dd>{ &props.version.build.timestamp }</dd>

        </dl>
    )
}
