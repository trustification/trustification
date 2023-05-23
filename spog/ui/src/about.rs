use crate::hooks::use_backend;
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(About)]
pub fn about() -> Html {
    let backend = use_backend();

    html!(
        <Bullseye plain=true>
            <patternfly_yew::prelude::About
                brand_src="https://www.patternfly.org/assets/images/PF-Masthead-Logo.svg"
                brand_alt="Chicken logo"
                title="Chicken Coop"
                strapline={html!("Copyright © 2020, 2023 by the Chickens")}
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
                        <dt>{ "Backend" }</dt>
                        <dd>{ backend.url.to_string() }</dd>
                    </dl>
                </Content>
            </patternfly_yew::prelude::About>
        </Bullseye>
    )
}
