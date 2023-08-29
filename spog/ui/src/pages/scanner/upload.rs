use crate::components::theme::ThemeContext;
use crate::hooks::use_config;
use monaco::api::{CodeEditorOptions, TextModel};
use monaco::sys::editor::BuiltinTheme;
use monaco::yew::CodeEditor;
use patternfly_yew::prelude::*;
use std::rc::Rc;
use wasm_bindgen_futures::JsFuture;
use yew::prelude::*;
use yew_hooks::prelude::*;
use yew_more_hooks::hooks::r#async::{UseAsyncState, *};

#[derive(Clone, Debug, PartialEq)]
enum DropContent {
    None,
    Files(Vec<web_sys::File>),
    Text(Rc<String>),
    Uri(Rc<String>),
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
            Self::Uri(uri) => f.write_str(uri),
            Self::Text(_) => f.write_str("User Input"),
            Self::None => Ok(()),
        }
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct UploadProperties {
    pub onsubmit: Callback<Rc<String>>,
    #[prop_or(default_validate())]
    pub onvalidate: Callback<Rc<String>, Result<Rc<String>, String>>,
}

fn default_validate() -> Callback<Rc<String>, Result<Rc<String>, String>> {
    Callback::from(Ok)
}

#[function_component(Upload)]
pub fn upload(props: &UploadProperties) -> Html {
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
            onuri: {
                let drop_content = drop_content.clone();
                Some(Box::new(move |uri, _data_transfer| {
                    drop_content.set(DropContent::Uri(Rc::new(uri)));
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
                DropContent::Uri(uri) => Rc::new(uri.to_string()),
                DropContent::None => Default::default(),
            };

            if content.is_empty() {
                // return early if the content is empty
                Err((Default::default(), "Requires an SBOM".to_string()))
            } else {
                // return success, as validated JSON
                onvalidate.emit(content.clone()).map_err(|err| (content, err))
            }
        },
        (drop_content.clone(), props.onvalidate.clone()),
    );

    let onclear = use_callback(
        |_: MouseEvent, drop_content| {
            // clear state
            drop_content.set(DropContent::None);
        },
        drop_content.clone(),
    );

    /*
    let helper_text = processing
        .error()
        .map(|err| FormHelperText::from((err.1.to_string(), InputState::Error)));
     */
    let (state, helper_text) = processing.error().map(
        |err| (InputState::Error, html_nested!(
            <HelperTextItem icon={HelperTextItemIcon::Visible} variant={ HelperTextItemVariant::Error }> { err.1.to_string() } </HelperTextItem>
        )),
    ).unzip();
    let state = state.unwrap_or_default();
    //let state = processing.error().is_some().then(||In).unwrap_or_default();

    let content = match &*processing {
        UseAsyncState::Ready(Ok(content)) => content.clone(),
        UseAsyncState::Ready(Err((content, _))) => content.clone(),
        _ => Default::default(),
    };

    use_effect_with_deps(
        |(initial, content)| {
            if !content.is_empty() {
                // only set the first, to remember we had some content
                initial.set(false);
            }
        },
        (initial.clone(), content.clone()),
    );

    let onsubmit = use_callback(
        |_: MouseEvent, (processing, onsubmit)| {
            if let Some(data) = processing.data() {
                onsubmit.emit(data.clone());
            }
        },
        (processing.clone(), props.onsubmit.clone()),
    );

    let file_input_ref = use_node_ref();
    let onopen = use_callback(
        |_: (), file_input_ref| {
            if let Some(ele) = file_input_ref.cast::<web_sys::HtmlElement>() {
                ele.click();
            }
        },
        file_input_ref.clone(),
    );
    let onopen_button = use_memo(|onopen| onopen.reform(|_: MouseEvent| ()), onopen.clone());

    let onchange_open = use_callback(
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
                drop_content.set(DropContent::Files(files));
            }
        },
        (file_input_ref.clone(), drop_content.clone()),
    );

    let oninput_text = use_callback(
        |text: String, drop_content| {
            drop_content.set(DropContent::from(text));
        },
        drop_content.clone(),
    );

    let mut class = classes!("tc-c-editor__wrapper");
    if *drop.over {
        class.push("pf-m-drag-over")
    }

    // build empty state actions

    let load_action = Action::new("Load", onopen);
    let mut secondaries = vec![];

    let config = use_config();
    let onlearn = use_callback(
        |_, url| {
            if let Some(url) = &url {
                let _ = gloo_utils::window().open_with_url_and_target(url.as_ref(), "_blank");
            }
        },
        config.scanner.documentation_url.clone(),
    );
    if config.scanner.documentation_url.is_some() {
        secondaries.push(Action::new("Learn creating an SBOM", onlearn));
    }

    // render

    html!(
        <div ref={node.clone()} {class}>
            <input ref={file_input_ref.clone()} style="display: none;" type="file" onchange={onchange_open} />
            <Stack gutter=true>
                <StackItem fill=true>
                    if *initial {
                        <EmptyState
                            title="Provide an SBOM"
                            icon={Icon::Code}
                            size={Size::XXXXLarge}
                            primary={load_action}
                            {secondaries}
                            full_height=true
                        >
                            { "Drop a file here or load one to scan it." }
                        </EmptyState>
                    }
                    if !*initial {
                        <Editor content={content.clone()} />
                    }
                </StackItem>
                <StackItem>
                    if !*initial {
                        <Flex>
                            <FlexItem>
                                <Button
                                    disabled={processing.is_processing()}
                                    variant={ButtonVariant::Secondary}
                                    onclick={(*onopen_button).clone()}
                                >
                                    {"Load"}
                                </Button>
                            </FlexItem>
                            <FlexItem>
                                <Button
                                    variant={ButtonVariant::Primary}
                                    disabled={state == InputState::Error}
                                    onclick={onsubmit}
                                >
                                    {"Scan"}
                                </Button>
                            </FlexItem>
                            <FlexItem>
                                <Button
                                    variant={ButtonVariant::Secondary}
                                    disabled={drop_content.is_none()}
                                    onclick={onclear}
                                >
                                    {"Clear"}
                                </Button>
                            </FlexItem>
                            <FlexItem>
                                if let Some(helper_text) = helper_text {
                                    <HelperText>
                                        { helper_text }
                                    </HelperText>
                                }
                            </FlexItem>
                        </Flex>
                    }
                </StackItem>
            </Stack>
        </div>
    )
}

#[derive(PartialEq, Properties)]
pub struct EditorProperties {
    pub content: Rc<String>,
}

#[function_component(Editor)]
fn editor(props: &EditorProperties) -> Html {
    let dark = use_context::<ThemeContext>()
        .map(|ctx| ctx.settings.dark)
        .unwrap_or_default();

    let theme = match dark {
        true => BuiltinTheme::VsDark,
        false => BuiltinTheme::Vs,
    };

    let options = use_memo(
        |theme| {
            let options = CodeEditorOptions::default()
                .with_scroll_beyond_last_line(false)
                .with_language("json".to_string())
                .with_builtin_theme(*theme)
                .with_automatic_layout(true)
                .to_sys_options();

            options.set_read_only(Some(true));

            options
        },
        theme,
    );

    let model = use_memo(
        |content| TextModel::create(content, Some("json"), None).unwrap(),
        props.content.clone(),
    );

    html!(
        <CodeEditor
            classes="tc-c-editor__code_editor"
            model={(*model).clone()}
            options={(*options).clone()}
        />
    )
}
