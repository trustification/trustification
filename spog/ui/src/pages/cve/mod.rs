mod result;

use patternfly_yew::prelude::*;
use result::ResultView;
use spog_ui_components::common::PageHeading;
use spog_ui_navigation::AppRoute;
use yew::prelude::*;
use yew_nested_router::prelude::*;

#[derive(PartialEq, Properties)]
pub struct CveProperties {
    pub id: Option<String>,
}

#[function_component(Cve)]
pub fn cve(props: &CveProperties) -> Html {
    match &props.id {
        Some(id) => html!(<ResultView id={id.clone()} />),
        None => html!(<SearchView/>),
    }
}

#[function_component(SearchView)]
fn search_view() -> Html {
    let text = use_state_eq(String::new);
    let onchange = use_callback(text.clone(), |value, text| text.set(value));

    let router = use_router::<AppRoute>();

    let submit_cb = use_callback(text.clone(), move |(), text| {
        if let Some(router) = &router {
            router.push(AppRoute::Cve { id: (**text).clone() });
        }
    });
    let onclick = (*use_memo(submit_cb.clone(), |cb| cb.reform(|_: MouseEvent| ()))).clone();
    let onsubmit = (*use_memo(submit_cb, |cb| cb.reform(|_: SubmitEvent| ()))).clone();

    html!(
        <>
            <PageHeading subtitle="Get information for an individual CVE">{"CVE Lookup"}</PageHeading>
            <PageSection>
                <Card>
                    <CardBody>

                        <form {onsubmit}>
                            // needed to trigger submit when pressing enter in the search field
                            <input type="submit" hidden=true formmethod="dialog" />

                            <Bullseye>
                                <Flex>
                                    <FlexItem>
                                        <TextInputGroup style="--pf-v5-c-text-input-group__text-input--MinWidth: 64ch;">
                                            <TextInputGroupMain
                                                icon={Icon::Search}
                                                value={(*text).clone()}
                                                placeholder="Search for a CVE ID"
                                                {onchange}
                                                autofocus=true
                                            />
                                        </TextInputGroup>
                                    </FlexItem>

                                    <FlexItem>
                                        <Button
                                            variant={ButtonVariant::Primary}
                                            label="Search"
                                            {onclick}
                                        />
                                    </FlexItem>
                                </Flex>
                            </Bullseye>
                        </form>

                    </CardBody>
                </Card>
            </PageSection>
        </>
    )
}
