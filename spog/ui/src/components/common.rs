use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew::virtual_dom::VList;

#[derive(Clone, PartialEq, Properties)]
pub struct PageHeadingProperties {
    pub children: Children,
    #[prop_or_default]
    pub subtitle: Option<String>,
    #[prop_or(true)]
    pub sticky: bool,
}

#[function_component(PageHeading)]
pub fn page_heading(props: &PageHeadingProperties) -> Html {
    let sticky = match props.sticky {
        true => vec![PageSectionSticky::Top],
        false => vec![],
    };
    html!(
        <PageSection {sticky} variant={PageSectionVariant::Light} >
            <Content>
                <Title>{ for props.children.iter() }</Title>
                if let Some(subtitle) = &props.subtitle {
                    <p>{ &subtitle }</p>
                }
            </Content>
        </PageSection>
    )
}

#[derive(Properties, PartialEq)]
pub struct Props {
    pub html: AttrValue,
    #[prop_or("div".into())]
    pub element: AttrValue,
}

/// Inject HTML that **is supposed to be safe**.
#[function_component(SafeHtml)]
pub fn safe_html(props: &Props) -> Html {
    let node = use_memo(
        |(element, html)| {
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
        },
        (props.element.clone(), props.html.clone()),
    );

    (*node).clone()
}

#[function_component(NotFound)]
pub fn not_found() -> Html {
    html!(
        <EmptyState
            title="Not found"
            icon={Icon::Search}
            size={Size::Small}
        >
            { "The content requested could not be found." }
        </EmptyState>
    )
}

#[derive(PartialEq, Properties)]
pub struct CardWrapperProperties {
    pub title: AttrValue,

    #[prop_or_default]
    pub children: Children,

    #[prop_or_default]
    pub plain: bool,
}

#[function_component(CardWrapper)]
pub fn card_wrapper(props: &CardWrapperProperties) -> Html {
    let title = html!(<Title>{ &props.title }</Title>);
    html!(
        <Card plain={props.plain} {title}>
            <CardBody>
                { for props.children.iter() }
            </CardBody>
        </Card>
    )
}

#[derive(PartialEq, Properties)]
pub struct ExternalNavLinkProperties {
    pub href: AttrValue,
    pub children: Children,
}

#[function_component(ExternalNavLink)]
pub fn ext_nav_link(props: &ExternalNavLinkProperties) -> Html {
    html!(
        <NavLink target="_blank" href={&props.href}>
            { for props.children.iter() }
            {" "}
            <ExternalLinkMarker/>
        </NavLink>
    )
}

#[function_component(ExternalLinkMarker)]
pub fn ext_link_marker() -> Html {
    html!({ Icon::ExternalLinkAlt.with_classes(classes!("pf-v5-u-ml-sm", "pf-v5-u-color-200")) })
}

#[derive(PartialEq, Properties)]
pub struct VisibleProperties {
    pub visible: bool,
    pub children: Children,
}

#[function_component(Visible)]
pub fn visible(props: &VisibleProperties) -> Html {
    let class = match props.visible {
        true => classes!(),
        false => classes!("pf-v5-u-display-none"),
    };

    html!(
        <div {class}>
            { for props.children.iter() }
        </div>
    )
}
