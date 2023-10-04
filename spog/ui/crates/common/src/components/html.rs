use yew::prelude::*;
use yew::virtual_dom::VList;

#[derive(Properties, PartialEq)]
pub struct SafeHtmlProperties {
    pub html: AttrValue,
    #[prop_or("div".into())]
    pub element: AttrValue,
}

/// Inject HTML that **is supposed to be safe**.
#[function_component(SafeHtml)]
pub fn safe_html(props: &SafeHtmlProperties) -> Html {
    let node = use_memo((props.element.clone(), props.html.clone()), |(element, html)| {
        if !html.is_empty() {
            let div = gloo_utils::document().create_element(element).unwrap();
            div.set_inner_html(html);

            let children = div.children();
            let len = children.length();

            let mut content = VList::new();
            match len > 0 {
                true => {
                    for i in 0..len {
                        let node = children.item(i);
                        if let Some(node) = node {
                            content.add_child(Html::VRef(node.into()));
                        }
                    }
                }
                false => content.add_child(Html::VRef(div.into())),
            };

            Html::VList(content)
        } else {
            // if it's empty, use the default
            Html::default()
        }
    });

    (*node).clone()
}
