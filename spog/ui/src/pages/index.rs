use crate::hooks::use_config;
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[function_component(Index)]
pub fn index() -> Html {
    let config = use_config();

    let text = use_state_eq(String::new);
    let onchange = use_callback(|new_text, text| text.set(new_text), text.clone());

    html!(
        <>
            { Html::from_html_unchecked(config.landing_page.content.clone().into()) }

            <PageSection variant={PageSectionVariant::Light}>
                <Bullseye>
                    <InputGroup>
                        <InputGroupItem>
                            <TextInputGroup>
                                <TextInputGroupMain
                                    icon={Icon::Search}
                                    value={(*text).clone()}
                                    {onchange}
                                />
                            </TextInputGroup>
                        </InputGroupItem>
                        <InputGroupItem>
                            <Button
                                variant={ButtonVariant::Control}
                                icon={Icon::ArrowRight}
                            />
                        </InputGroupItem>
                    </InputGroup>
                </Bullseye>
            </PageSection>

        </>
    )
}
