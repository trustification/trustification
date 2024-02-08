use patternfly_yew::prelude::*;
use std::rc::Rc;
use wasm_bindgen_futures::JsFuture;
use yew::prelude::*;
use yew_hooks::prelude::*;
use yew_more_hooks::hooks::r#async::{UseAsyncState, *};

use crate::editor::ReadonlyEditor;

#[derive(Clone, Debug, PartialEq)]
enum DropContent {
    None,
    Files(Vec<web_sys::File>),
    Text(Rc<String>),
}

impl From<String> for DropContent {
    fn from(value: String) -> Self {
        if value.is_empty() {
            Self::None
        } else {
            Self::Text(Rc::new(value))
        }
    }
}

impl DropContent {
    pub fn is_none(&self) -> bool {
        matches!(self, Self::None)
    }
}

impl std::fmt::Display for DropContent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        match self {
            Self::Files(files) => {
                for (n, name) in files.iter().map(|f| f.name()).enumerate() {
                    if n > 0 {
                        f.write_str(", ")?;
                    }
                    f.write_str(&name)?;
                }
                Ok(())
            }
            Self::Text(_) => f.write_str("User Input"),
            Self::None => Ok(()),
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct UploadFileProperties {
    #[prop_or_default]
    pub state_title: AttrValue,

    #[prop_or_default]
    pub state_content: Html,

    #[prop_or_default]
    pub primary_action_text: AttrValue,

    #[prop_or_default]
    pub secondary_actions: Vec<Action>,

    #[prop_or_default]
    pub submit_btn_text: AttrValue,

    pub onsubmit: Callback<Rc<String>>,

    #[prop_or(default_validate())]
    pub onvalidate: Callback<Rc<String>, Result<Rc<String>, String>>,
}

fn default_validate() -> Callback<Rc<String>, Result<Rc<String>, String>> {
    Callback::from(Ok)
}

#[function_component(UploadFile)]
pub fn upload_file(props: &UploadFileProperties) -> Html {
    let node = use_node_ref();

    let initial = use_state_eq(|| true);

    let drop_content = use_state(|| DropContent::None);

    let drop = use_drop_with_options(
        node.clone(),
        UseDropOptions {
            onfiles: {
                let drop_content = drop_content.clone();
                Some(Box::new(move |files, _data_transfer| {
                    drop_content.set(DropContent::Files(files));
                }))
            },
            ontext: {
                let drop_content = drop_content.clone();
                Some(Box::new(move |text, _data_transfer| {
                    drop_content.set(DropContent::from(text));
                }))
            },
            onuri: Some(Box::new(move |_uri, _data_transfer| {})),
            ..Default::default()
        },
    );

    let processing = use_async_with_cloned_deps(
        |(content, onvalidate)| async move {
            let content = match &*content {
                DropContent::Files(files) => {
                    let mut content = String::new();
                    for file in files {
                        match JsFuture::from(file.text()).await {
                            Ok(data) => content.push_str(&data.as_string().unwrap_or_default()),
                            Err(err) => {
                                return Err((
                                    Default::default(),
                                    format!(
                                        "Failed to receive content: {err}",
                                        err = err.as_string().unwrap_or_default()
                                    ),
                                ))
                            }
                        }
                    }
                    Rc::new(content)
                }
                DropContent::Text(text) => Rc::new(text.to_string()),
                DropContent::None => Default::default(),
            };

            if content.is_empty() {
                // return early if the content is empty
                Err((Default::default(), "Requires a valid file".to_string()))
            } else {
                // return success, as validated JSON
                onvalidate.emit(content.clone()).map_err(|err| (content, err))
            }
        },
        (drop_content.clone(), props.onvalidate.clone()),
    );

    let onclear = use_callback(drop_content.clone(), |_: MouseEvent, drop_content| {
        // clear state
        drop_content.set(DropContent::None);
    });

    let state = processing.error().map(
        |(_, err)| (InputState::Error, html_nested!(
            <HelperTextItem icon={HelperTextItemIcon::Visible} variant={HelperTextItemVariant::Error}> { err.clone() } </HelperTextItem>
        )),
    );
    let (state, helper_text) = match state {
        Some((state, helper_text)) => (Some(state), Some(helper_text)),
        None => (None, None),
    };
    let state = state.unwrap_or_default();

    let content = match &*processing {
        UseAsyncState::Ready(Ok(content)) => content.clone(),
        UseAsyncState::Ready(Err((content, _))) => content.clone(),
        _ => Default::default(),
    };

    use_effect_with((initial.clone(), content.clone()), |(initial, content)| {
        initial.set(content.is_empty());
    });

    let onsubmit = use_callback(
        (processing.clone(), props.onsubmit.clone()),
        |_: MouseEvent, (processing, onsubmit)| {
            if let Some(data) = processing.data() {
                onsubmit.emit(data.clone());
            }
        },
    );

    let file_input_ref = use_node_ref();
    let onopen = use_callback(file_input_ref.clone(), |_: (), file_input_ref| {
        if let Some(ele) = file_input_ref.cast::<web_sys::HtmlElement>() {
            ele.click();
        }
    });
    let onopen_button = use_memo(onopen.clone(), |onopen| onopen.reform(|_: MouseEvent| ()));

    let onchange_open = use_callback(
        (file_input_ref.clone(), drop_content.clone()),
        |_, (file_input_ref, drop_content)| {
            if let Some(ele) = file_input_ref.cast::<web_sys::HtmlInputElement>() {
                let files = ele
                    .files()
                    .map(|files| {
                        let mut r = Vec::with_capacity(files.length().try_into().unwrap_or_default());
                        for i in 0..files.length() {
                            r.extend(files.get(i));
                        }
                        r
                    })
                    .unwrap_or_default();
                ele.set_value("");
                drop_content.set(DropContent::Files(files));
            }
        },
    );

    let mut class = classes!("tc-c-drop-area");
    if *drop.over {
        class.push("pf-m-drag-over")
    }

    // build empty state actions

    let load_action = Action::new(&props.primary_action_text, onopen);

    let footer = html!(
        <Flex>
            <FlexItem>
                <Button
                    id="file-load"
                    disabled={processing.is_processing()}
                    variant={ButtonVariant::Secondary}
                    onclick={(*onopen_button).clone()}
                >
                    {"Load"}
                </Button>
            </FlexItem>
            <FlexItem>
                <Button
                    id="file-submit"
                    variant={ButtonVariant::Primary}
                    disabled={state == InputState::Error}
                    onclick={onsubmit}
                >
                    {&props.submit_btn_text}
                </Button>
            </FlexItem>
            <FlexItem>
                <Button
                    id="file-clear"
                    variant={ButtonVariant::Secondary}
                    disabled={drop_content.is_none()}
                    onclick={onclear}
                >
                    {"Clear"}
                </Button>
            </FlexItem>
            <FlexItem>
                if let Some(helper_text) = helper_text {
                    <HelperText id="file-help-text" live_region=true>
                        { helper_text }
                    </HelperText>
                }
            </FlexItem>
        </Flex>
    );

    // render

    html!(
        <>
            <Stack gutter=true>
                <StackItem fill=true>
                    <Card
                        full_height=true
                        plain=true
                        style="--pf-v5-c-card--BackgroundColor: var(--pf-v5-global--BackgroundColor--200);"
                        size={CardSize::Compact}
                    >
                        <CardBody>
                            <div ref={node.clone()} {class} style="background-color: var(--pf-v5-global--BackgroundColor--100);">
                                <input ref={file_input_ref.clone()} style="display: none;" type="file" onchange={onchange_open} />
                                if *initial {
                                    <EmptyState
                                        title={props.state_title.to_string()}
                                        icon={Icon::Code}
                                        size={Size::XXXXLarge}
                                        primary={load_action}
                                        secondaries={props.secondary_actions.clone()}
                                        full_height=true
                                    >
                                        <Content>
                                            {props.state_content.clone()}
                                        </Content>
                                    </EmptyState>
                                }
                                if !*initial {
                                    <ReadonlyEditor content={content.clone()} />
                                }
                            </div>
                        </CardBody>
                    </Card>
                </StackItem>
                <StackItem>
                    if !*initial {
                        {footer}
                    }
                </StackItem>
            </Stack>

        </>

    )
}
