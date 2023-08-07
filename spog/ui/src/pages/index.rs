use crate::hooks::use_config;
use crate::pages::AppRoute;
use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_nested_router::prelude::*;

#[function_component(Index)]
pub fn index() -> Html {
    let config = use_config();

    let text = use_state_eq(String::new);
    let onchange = use_callback(|new_text, text| text.set(new_text), text.clone());

    let router = use_router::<AppRoute>();
    let onclick = use_callback(
        |_, (router, terms)| {
            if let Some(router) = router {
                router.push(AppRoute::Search {
                    terms: (**terms).clone(),
                });
            }
        },
        (router.clone(), text.clone()),
    );
    let onsubmit = use_callback(
        |_, (router, terms)| {
            if let Some(router) = router {
                router.push(AppRoute::Search {
                    terms: (**terms).clone(),
                });
            }
        },
        (router.clone(), text.clone()),
    );

    html!(
        <>
            { Html::from_html_unchecked(config.landing_page.content.clone().into()) }

            <PageSection variant={PageSectionVariant::Light}>
                <Bullseye>
                    <Form {onsubmit}>
                        // needed to trigger submit when pressing enter in the search field
                        <input type="submit" hidden=true formmethod="dialog" />
                        <InputGroup>
                            <InputGroupItem>
                                <TextInputGroup>
                                    <TextInputGroupMain
                                        icon={Icon::Search}
                                        value={(*text).clone()}
                                        {onchange}
                                        autofocus=true
                                    />
                                </TextInputGroup>
                            </InputGroupItem>
                            <InputGroupItem>
                                <Button
                                    variant={ButtonVariant::Control}
                                    icon={Icon::ArrowRight}
                                    {onclick}
                                />
                            </InputGroupItem>
                        </InputGroup>
                    </Form>
                </Bullseye>
            </PageSection>

        </>
    )
}
