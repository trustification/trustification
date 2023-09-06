mod inspect;
// mod unknown;
mod report;
mod upload;

use crate::analytics::use_tracking;
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
                    <PageSection variant={PageSectionVariant::Default} fill=true>
                        <Card
                            title={html!(<Title> {"SBOM content"} </Title>)}
                            full_height=true
                        >
                            <CardBody>
                                <Upload {onsubmit} {onvalidate}/>
                            </CardBody>
                        </Card>
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

    let onlearn = use_tracking(|_, _| ClickLearn, ());

    html!(
        <PageSection sticky={[PageSectionSticky::Top]} variant={PageSectionVariant::Light}>
            <Flex>
                <FlexItem>
                    <Content>
                        <Title>{"Scan an SBOM"}</Title>
                    </Content>
                </FlexItem>
                <FlexItem modifiers={[FlexModifier::Align(Alignment::Right), FlexModifier::Align(Alignment::End)]}>
                    if let Some(url) = &config.scanner.documentation_url {
                        <a
                            href={url.to_string()} target="_blank"
                            class="pf-v5-c-button pf-m-plain"
                            onclick={onlearn}
                        >
                            { Icon::QuestionCircle }
                        </a>
                    }
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
