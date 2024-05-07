use crate::components::SafeHtml;
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct MarkdownProperties {
    pub content: Rc<String>,
}

#[function_component(Markdown)]
pub fn markdown(props: &MarkdownProperties) -> Html {
    let content = use_memo(props.content.clone(), |content| {
        markdown::to_html_with_options(content.as_str(), &markdown::Options::gfm())
            .map(AttrValue::from)
            .unwrap_or_else(|_| AttrValue::from((*props.content).clone()))
    });

    html!(<SafeHtml html={(*content).clone()}/>)
}
