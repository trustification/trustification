use patternfly_yew::prelude::*;
use wasm_bindgen_futures::JsFuture;
use yew::prelude::*;
use yew_hooks::prelude::*;
use yew_more_hooks::hooks::r#async::{UseAsyncState, *};

#[derive(Clone, Debug, PartialEq)]
enum DropContent {
    None,
    Files(Vec<web_sys::File>),
    Text(String),
    Uri(String),
}

impl From<String> for DropContent {
    fn from(value: String) -> Self {
        if value.is_empty() {
            Self::None
        } else {
            Self::Text(value)
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
            Self::Uri(uri) => f.write_str(&uri),
            Self::Text(_) => f.write_str("User Input"),
            Self::None => Ok(()),
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct UploadProperties {
    pub onsubmit: Callback<String>,
    #[prop_or(default_validate())]
    pub onvalidate: Callback<String, Result<String, String>>,
}

fn default_validate() -> Callback<String, Result<String, String>> {
    Callback::from(|data| Ok(data))
}

#[function_component(Upload)]
pub fn upload(props: &UploadProperties) -> Html {
    let node = use_node_ref();

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
            onuri: {
                let drop_content = drop_content.clone();
                Some(Box::new(move |uri, _data_transfer| {
                    drop_content.set(DropContent::Uri(uri));
                }))
            },
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
                                    String::new(),
                                    format!(
                                        "Failed to receive content: {err}",
                                        err = err.as_string().unwrap_or_default()
                                    ),
                                ))
                            }
                        }
                    }
                    content
                }
                DropContent::Text(text) => text.to_string(),
                DropContent::Uri(uri) => uri.to_string(),
                DropContent::None => "".to_string(),
            };

            if content.is_empty() {
                // return early if the content is empty
                Err((String::new(), "Requires an SBOM".to_string()))
            } else {
                // return success, as validated JSON
                onvalidate.emit(content.clone()).map_err(|err| (content, err))
            }
        },
        (drop_content.clone(), props.onvalidate.clone()),
    );

    let onclear = use_callback(
        |_, drop_content| {
            // clear state
            drop_content.set(DropContent::None);
        },
        drop_content.clone(),
    );

    let helper_text = processing
        .error()
        .map(|err| FormHelperText::from((err.1.to_string(), InputState::Error)));
    let state = helper_text.as_ref().map(|h| h.input_state).unwrap_or_default();
    let content = use_memo(
        |processing| match &**processing {
            UseAsyncState::Ready(Ok(content)) => content.clone(),
            UseAsyncState::Ready(Err((content, _))) => content.clone(),
            _ => String::new(),
        },
        processing.clone(),
    );

    let onsubmit = use_callback(
        |_, (processing, onsubmit)| {
            if let Some(data) = processing.data() {
                onsubmit.emit(data.clone());
            }
        },
        (processing.clone(), props.onsubmit.clone()),
    );

    let file_input_ref = use_node_ref();
    let onopen = use_callback(
        |_, file_input_ref| {
            if let Some(ele) = file_input_ref.cast::<web_sys::HtmlElement>() {
                ele.click();
            }
        },
        file_input_ref.clone(),
    );

    let onchange_open = use_callback(
        || {
            if let Some(ele) = file_input_ref.cast::<web_sys::HtmlInputElement>() {
                let files = ele
                    .files()
                    .map(|files| {
                        let mut r = Vec::with_capacity(files.length().try_into().unwrap_or_default());
                        for i in 0..files.length() {
                            Extend::extend(&mut r, files.get(i));
                        }
                        r
                    })
                    .unwrap_or_default();
                drop_content.set(DropContent::Files(files));
            }
        },
        (file_input_ref, drop_content),
    );

    let oninput_text = use_callback(
        |text, drop_content| {
            drop_content.set(DropContent::from(text));
        },
        drop_content.clone(),
    );

    html!(
        <div ref={node.clone()}>
            <Form>
                <FormGroup
                    {helper_text}
                >
                    <FileUpload
                        drag_over={*drop.over}
                    >
                        <FileUploadSelect>
                            <InputGroup>
                                <TextInput readonly=true value={(*drop_content).to_string()}/>
                                <input ref={file_input_ref.clone()} style="display: none;" type="file" onchange={onchange_open} />
                                <Button
                                    variant={ButtonVariant::Control}
                                    disabled={processing.is_processing()}
                                    onclick={onopen}
                                >
                                    {"Open"}
                                </Button>
                                <Button
                                    variant={ButtonVariant::Control}
                                    disabled={state == InputState::Error}
                                    onclick={onsubmit}
                                >
                                    {"Inspect"}
                                </Button>
                                <Button
                                    variant={ButtonVariant::Control}
                                    onclick={onclear}
                                    disabled={drop_content.is_none()}>
                                    {"Clear"}
                                </Button>
                            </InputGroup>
                        </FileUploadSelect>
                        <FileUploadDetails
                            processing={processing.is_processing()}
                            invalid={state == InputState::Error}
                        >
                            <TextArea
                                value={(*content).clone()}
                                resize={ResizeOrientation::Vertical}
                                oninput={oninput_text}
                                rows={20}
                                readonly=true
                                {state}
                            />
                        </FileUploadDetails>
                    </FileUpload>
                </FormGroup>
            </Form>
        </div>
    )
}
