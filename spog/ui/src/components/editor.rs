use crate::components::theme::ThemeContext;
use monaco::api::{CodeEditorOptions, TextModel};
use monaco::sys::editor::BuiltinTheme;
use monaco::yew::CodeEditor;
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct ReadonlyEditorProperties {
    pub content: Rc<String>,
}

#[function_component(ReadonlyEditor)]
pub fn readonly_editor(props: &ReadonlyEditorProperties) -> Html {
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
            classes="tc-c-editor"
            model={(*model).clone()}
            options={(*options).clone()}
        />
    )
}
