use crate::{
    backend::VersionService,
    hooks::{use_backend, use_config},
};
use patternfly_yew::prelude::*;
use std::rc::Rc;
use trustification_version::{version, VersionInformation};
use yew::prelude::*;
use yew_more_hooks::hooks::*;
use yew_oauth2::hook::use_latest_access_token;

#[function_component(About)]
pub fn about() -> Html {
    let config = use_config();
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let version = use_memo(|()| version!(), ());

    let remote = use_async_with_cloned_deps(
        |backend| async {
            VersionService::new(backend, access_token)
                .get_version()
                .await
                .map(Rc::new)
        },
        backend.clone(),
    );

    let brand_image_src = config.global.brand_image_src();
    let background_image_src = config.global.about_background_src();
    let product_name = config.global.product_name();

    html!(
        <Bullseye plain=true>
            <AboutModal
                {brand_image_src}
                brand_image_alt="Brand Logo"
                {background_image_src}
                {product_name}
                trademark="Copyright © 2020, 2023 by the Chickens"
            >
                <Content>
                    <p>{ &version.description }</p>
                    // width is required to better align
                    <dl style="width: 100%">
                        <dt>{ "Frontend" }</dt>
                        <dd>
                            <VersionInfo {version}/>
                        </dd>

                        <dt>{ "Backend" }</dt>
                        <dd>
                            <p> { backend.endpoints.url.to_string() } </p>
                            {
                                match &*remote {
                                    UseAsyncState::Pending | UseAsyncState::Processing => {
                                        html!( <Spinner/> )
                                    },
                                    UseAsyncState::Ready(Ok(result)) => {
                                        html!(<>
                                            <VersionInfo version={result.clone()} />
                                        </>)
                                    },
                                    UseAsyncState::Ready(Err(err)) => html! (
                                        format!("Failed to retrieve version: {err}")
                                    ),
                                }
                            }
                        </dd>
                    </dl>

                </Content>
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
            <dd>{ &props.version.version.full }</dd>
            if let Some(info) = &props.version.git.describe {
                <dt>{ "Git" }</dt>
                <dd>{ &info }</dd>
            }
            <dt>{ "Build timestamp" }</dt>
            <dd>{ &props.version.build.timestamp }</dd>

        </dl>
    )
}
