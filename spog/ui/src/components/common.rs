use patternfly_yew::prelude::*;
use yew::prelude::*;

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
    pub html: String,
}

#[function_component(SafeHtml)]
pub fn safe_html(props: &Props) -> Html {
    let div = gloo_utils::document().create_element("div").unwrap();
    div.set_inner_html(&props.html.clone());

    Html::VRef(div.into())
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
