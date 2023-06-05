use crate::hooks::use_backend;
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(About)]
pub fn about() -> Html {
    let backend = use_backend();

    html!(
        <Bullseye plain=true>
            <patternfly_yew::prelude::AboutModal
                brand_image_src="assets/images/chicken-svgrepo-com.svg"
                brand_image_alt="Chicken logo"
                product_name="Chicken Coop"
                trademark="Copyright © 2020, 2023 by the Chickens"
                background_image_src="https://www.patternfly.org/assets/images/pfbg_992.jpg"
                hero_style=r#"
--pf-c-about-modal-box__hero--lg--BackgroundImage: url("https://www.patternfly.org/assets/images/pfbg_992@2x.jpg");
--pf-c-about-modal-box__hero--sm--BackgroundImage: url("https://www.patternfly.org/assets/images/pfbg_992.jpg");
"#
            >
                <Content>
                    <p>{ env!("CARGO_PKG_DESCRIPTION") }</p>
                    <dl style="width: 100%">
                        <dt>{ "Version" }</dt>
                        <dd>{ env!("CARGO_PKG_VERSION") }</dd>
                        <dt>{ "License" }</dt>
                        <dd>{ env!("CARGO_PKG_LICENSE") }</dd>
                        if let Some(commit) = option_env!("BUILD_COMMIT") {
                            <dt>{ "Commit" }</dt>
                            <dd>{ commit }</dd>
                        }
                        if let Some(tag) = option_env!("TAG") {
                            <dt>{ "Tag" }</dt>
                            <dd>{ tag }</dd>
                        }
                        <dt>{ "Backend" }</dt>
                        <dd>{ backend.endpoints.url.to_string() }</dd>
                    </dl>
                </Content>
            </patternfly_yew::prelude::AboutModal>
        </Bullseye>
    )
}
