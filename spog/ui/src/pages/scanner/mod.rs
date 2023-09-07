mod inspect;
// mod unknown;
mod report;
mod upload;

use crate::analytics::use_tracking;
use crate::hints::Hints;
use crate::hooks::use_config;
use analytics_next::TrackingEvent;
use anyhow::bail;
use bombastic_model::prelude::SBOM;
use gloo_utils::window;
use inspect::Inspect;
use patternfly_yew::prelude::*;
use serde_json::{json, Value};
use std::rc::Rc;
use upload::Upload;
use yew::prelude::*;
use yew_hooks::use_local_storage;

pub struct ClickLearn;

impl From<ClickLearn> for TrackingEvent<'static> {
    fn from(_: ClickLearn) -> Self {
        (
            "Click SBOM scanner learn",
            json!({
                "page": window().location().href().ok(),
            }),
        )
            .into()
    }
}

fn parse(data: &[u8]) -> Result<SBOM, anyhow::Error> {
    let sbom = SBOM::parse(data)?;

    #[allow(clippy::single_match)]
    match &sbom {
        SBOM::CycloneDX(_bom) => {
            // re-parse to check for the spec version
            let json = serde_json::from_slice::<Value>(data).ok();
            let spec_version = json.as_ref().and_then(|json| json["specVersion"].as_str());
            match spec_version {
                Some("1.3") => {}
                Some(other) => bail!("Unsupported CycloneDX version: {other}"),
                None => bail!("Unable to detect CycloneDX version"),
            }
        }
        _ => {}
    }

    Ok(sbom)
}

#[function_component(Scanner)]
pub fn scanner() -> Html {
    let content = use_state_eq(|| None::<Rc<String>>);
    let onsubmit = use_callback(|data, content| content.set(Some(data)), content.clone());

    let sbom = use_memo(
        |content| {
            content
                .as_ref()
                .and_then(|data| parse(data.as_bytes()).ok().map(|sbom| (data.clone(), Rc::new(sbom))))
        },
        content.clone(),
    );

    let onvalidate = use_callback(
        |data: Rc<String>, ()| match parse(data.as_bytes()) {
            Ok(_sbom) => Ok(data),
            Err(err) => Err(format!("Failed to parse SBOM as CycloneDX 1.3: {err}")),
        },
        (),
    );

    // allow resetting the form
    let onreset = use_callback(
        |_, content| {
            content.set(None);
        },
        content.clone(),
    );

    match &*sbom {
        Some((raw, _bom)) => {
            html!(<Inspect {onreset} raw={(*raw).clone()} />)
        }
        None => {
            html!(
                <>
                    <CommonHeader />

                    <WelcomeHint />

                    <PageSection variant={PageSectionVariant::Light} fill=true>
                        <Card
                            full_height=true
                            style="--pf-v5-c-card--BackgroundColor: var(--pf-v5-global--BackgroundColor--200);"
                            compact=true
                        >
                            <CardBody>
                                <Upload {onsubmit} {onvalidate} />
                            </CardBody>
                        </Card>
                    </PageSection>
                </>
            )
        }
    }
}

#[function_component(WelcomeHint)]
fn welcome_hint() -> Html {
    let hint_state = use_local_storage::<bool>(Hints::ScannerWelcome.to_string());

    let hide = (*hint_state).unwrap_or_default();

    let onhide = use_callback(
        |_, hint_state| {
            hint_state.set(true);
        },
        hint_state.clone(),
    );

    let title = html!(<Title>{ "Receive a detailed summary of your SBOM stack including:" }</Title>);
    let actions = Some(html!(
        <Button onclick={onhide} variant={ButtonVariant::Plain}> { Icon::Times } </Button>
    ));

    html!(
        if !hide {
            <PageSection
                variant={PageSectionVariant::Light}
                r#type={PageSectionType::Breadcrumbs}
            >
                <Card {actions} {title}
                    style="--pf-v5-c-card--BackgroundColor: var(--pf-v5-global--BackgroundColor--200);"
                >
                    <CardBody>
                        <Flex>
                            <FlexItem>
                                {"Security issues"}
                            </FlexItem>
                            <FlexItem>
                                {"Licenses"}
                            </FlexItem>
                            <FlexItem>
                                {"Dependency details"}
                            </FlexItem>
                        </Flex>
                    </CardBody>
                </Card>
            </PageSection>
        }
    )
}

#[derive(PartialEq, Properties)]
pub struct CommonHeaderProperties {
    #[prop_or_default]
    pub onreset: Option<Callback<()>>,
}

#[function_component(CommonHeader)]
fn common_header(props: &CommonHeaderProperties) -> Html {
    let config = use_config();

    let onlearn = use_tracking(|_, _| ClickLearn, ());

    html!(
        <PageSection sticky={[PageSectionSticky::Top]} variant={PageSectionVariant::Light}>
            <Flex>
                <FlexItem>
                    <Content>
                        <Title>{"Scan an SBOM"}</Title>
                        <p>
                            {"Load an existing CycloneDX 1.3 or SPDX 2.2 file"}
                            if let Some(url) = &config.scanner.documentation_url {
                                {" or "}
                                <a
                                    href={url.to_string()} target="_blank"
                                    class="pf-v5-c-button pf-m-link pf-m-inline"
                                    onclick={onlearn}
                                >
                                    {"learn about creating an SBOM"}
                                </a>
                            }
                            { "." }
                        </p>
                    </Content>
                </FlexItem>
                <FlexItem modifiers={[FlexModifier::Align(Alignment::Right), FlexModifier::Align(Alignment::End)]}>
                    if let Some(onreset) = &props.onreset {
                        <Button
                            label={"Scan another"}
                            icon={Icon::Redo}
                            variant={ButtonVariant::Secondary}
                            onclick={onreset.reform(|_|())}
                        />
                    }
                </FlexItem>
            </Flex>
        </PageSection>
    )
}
