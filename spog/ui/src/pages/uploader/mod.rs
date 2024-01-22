mod inspect;

use crate::pages::scanner::parse;
use crate::pages::scanner::upload::Upload;
use inspect::Inspect;
use patternfly_yew::prelude::*;
use spog_ui_utils::config::*;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[function_component(Uploader)]
pub fn uploader() -> Html {
    let content = use_state_eq(|| None::<Rc<String>>);
    let onsubmit = use_callback(content.clone(), |data, content| content.set(Some(data)));

    let sbom = use_memo(content.clone(), |content| {
        content
            .as_ref()
            .and_then(|data| parse(data.as_bytes()).ok().map(|sbom| (data.clone(), Rc::new(sbom))))
    });

    let onvalidate = use_callback((), |data: Rc<String>, ()| {
        let result = parse(data.as_bytes());
        match result {
            Ok(_sbom) => Ok(data),
            Err(err) => Err(format!("Failed to parse SBOM as CycloneDX 1.3: {err}")),
        }
    });

    // allow resetting the form
    let onreset = use_callback(content.clone(), move |_, content| {
        content.set(None);
    });

    match &*sbom {
        Some((raw, _bom)) => {
            html!(<Inspect {onreset} raw={(*raw).clone()} />)
        }
        None => {
            html!(
                <>
                    <CommonHeader />

                    <PageSection variant={PageSectionVariant::Light} fill=true>
                        <Upload primary_btn_text="Upload SBOM" {onsubmit} {onvalidate} />
                    </PageSection>
                </>
            )
        }
    }
}

#[derive(PartialEq, Properties)]
pub struct CommonHeaderProperties {
    #[prop_or_default]
    pub onreset: Option<Callback<()>>,
}

#[function_component(CommonHeader)]
fn common_header(props: &CommonHeaderProperties) -> Html {
    let config = use_config();

    let onreset = use_map(props.onreset.clone(), move |callback| callback.reform(|_| ()));

    html!(
        <PageSection sticky={[PageSectionSticky::Top]} variant={PageSectionVariant::Light}>
            <Flex>
                <FlexItem>
                    <Content>
                        <Title>{"Upload an SBOM"}</Title>
                        <p>
                            {"Load an existing CycloneDX 1.3 or SPDX 2.2 file"}
                            if let Some(url) = &config.scanner.documentation_url {
                                {" or "}
                                <a
                                    href={url.to_string()} target="_blank"
                                    class="pf-v5-c-button pf-m-link pf-m-inline"
                                >
                                    {"learn about creating an SBOM"}
                                </a>
                            }
                            { "." }
                        </p>
                    </Content>
                </FlexItem>
                <FlexItem modifiers={[FlexModifier::Align(Alignment::Right), FlexModifier::Align(Alignment::End)]}>
                    if let Some(onreset) = onreset {
                        <Button
                            label={"Scan another"}
                            icon={Icon::Redo}
                            variant={ButtonVariant::Secondary}
                            onclick={onreset}
                        />
                    }
                </FlexItem>
            </Flex>
        </PageSection>
    )
}
