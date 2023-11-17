use crate::hooks::use_related_advisories;
use patternfly_yew::prelude::*;
use spog_ui_components::async_state_renderer::async_content;
use spog_ui_navigation::{AppRoute, View};
use yew::prelude::*;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties)]
pub struct DetailsProperties {
    pub id: String,
}

#[function_component(Details)]
pub fn details(props: &DetailsProperties) -> Html {
    let advisories = use_related_advisories(props.id.clone());

    html!(
        <>
            <Content>
                { async_content(&advisories, |list| html!(
                    if !list.is_empty() {
                        <>
                            <Title level={Level::H4}> { "Relevant advisories" } </Title>
                            <List r#type={ListType::Basic}>
                                { for list.iter().map(|adv| html_nested! (
                                    <ListItem>
                                        <Link<AppRoute> target={AppRoute::Advisory(View::Content {id: adv.id.clone()})}>
                                            { adv.id.clone() }
                                        </Link<AppRoute>>
                                        {": "}{ adv.title.clone() }
                                    </ListItem>
                                )) }
                            </List>
                        </>
                    }
                ) )}

                <p>
                    <Link<AppRoute> target={AppRoute::Cve(View::Content {id: props.id.clone()})}>
                        {"All CVE details "} { Icon::ArrowRight }
                    </Link<AppRoute>>
                </p>
            </Content>
        </>
    )
}
