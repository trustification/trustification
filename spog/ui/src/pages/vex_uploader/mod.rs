mod inspect;

use inspect::Inspect;
use patternfly_yew::prelude::*;
use spog_ui_components::upload_file::UploadFile;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

const EMPTY_BODY_CONTENT: &str = r#"
<div>
    <p>Start by <strong>dragging and dropping a file here</strong> or clicking the <strong>Load a CSAF</strong> button.</p>
</div>
"#;

pub fn parse(data: &[u8]) -> Result<csaf::Csaf, anyhow::Error> {
    let vex = serde_json::from_slice::<csaf::Csaf>(data)?;
    Ok(vex)
}

#[function_component(VexUploader)]
pub fn vex_uploader() -> Html {
    let content = use_state_eq(|| None::<Rc<String>>);
    let onsubmit = use_callback(content.clone(), |data, content| content.set(Some(data)));

    let vex = use_memo(content.clone(), |content| {
        content
            .as_ref()
            .and_then(|data| parse(data.as_bytes()).ok().map(|sbom| (data.clone(), Rc::new(sbom))))
    });

    let onvalidate = use_callback((), |data: Rc<String>, ()| {
        let result = parse(data.as_bytes());
        match result {
            Ok(_sbom) => Ok(data),
            Err(err) => Err(format!("Failed to parse CSAF: {err}")),
        }
    });

    // allow resetting the form
    let onreset = use_callback(content.clone(), move |_, content| {
        content.set(None);
    });

    match &*vex {
        Some((raw, _bom)) => {
            html!(<Inspect {onreset} raw={(*raw).clone()} />)
        }
        None => {
            html!(
                <>
                    <CommonHeader />

                    <PageSection variant={PageSectionVariant::Light} fill=true>
                        <UploadFile
                            state_title="Get started by uploading your CSAF file"
                            state_content={Html::from_html_unchecked(AttrValue::from(EMPTY_BODY_CONTENT))}
                            primary_action_text="Load a CSAF"
                            submit_btn_text="Upload CSAF"
                            {onsubmit}
                            {onvalidate}
                        />
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
    let onreset = use_map(props.onreset.clone(), move |callback| callback.reform(|_| ()));

    html!(
        <PageSection sticky={[PageSectionSticky::Top]} variant={PageSectionVariant::Light}>
            <Flex>
                <FlexItem>
                    <Content>
                        <Title>{"Upload a CSAF file"}</Title>
                        <p>
                            {"Load an existing CSAF file."}
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
