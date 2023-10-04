mod result;

use patternfly_yew::prelude::*;
use result::ResultView;
use spog_ui_components::common::PageHeading;
use spog_ui_navigation::AppRoute;
use yew::prelude::*;
use yew_nested_router::prelude::*;

#[derive(PartialEq, Properties)]
pub struct PackageProperties {
    pub id: Option<String>,
}

#[function_component(Package)]
pub fn package(props: &PackageProperties) -> Html {
    match &props.id {
        Some(id) => html!(<ResultView id={id.clone()} />),
        None => html!(<SearchView/>),
    }
}

#[function_component(SearchView)]
fn search_view() -> Html {
    let inputtext = use_state_eq(String::new);
    let on_inputtext_change = use_callback(inputtext.clone(), |value, inputtext| inputtext.set(value));

    let router = use_router::<AppRoute>();

    let submit = use_callback(inputtext.clone(), move |(), inputtext| {
        if let Some(router) = &router {
            router.push(AppRoute::Package {
                id: (**inputtext).clone(),
            });
        }
    });

    let on_searchbtn_click = (*use_memo(submit.clone(), |submit| submit.reform(|_: MouseEvent| ()))).clone();
    let on_form_submit = (*use_memo(submit, |submit| submit.reform(|_: SubmitEvent| ()))).clone();

    html!(
        <>
            <PageHeading subtitle="Get information for an individual Package">{"Package Lookup"}</PageHeading>
            <PageSection>
                <Card>
                    <CardBody>
                        <form onsubmit={on_form_submit}>
                            // needed to trigger submit when pressing enter in the search field
                            <input type="submit" hidden=true formmethod="dialog" />

                            <Bullseye>
                                <Flex>
                                    <FlexItem>
                                        <TextInputGroup style="--pf-v5-c-text-input-group__text-input--MinWidth: 64ch;">
                                            <TextInputGroupMain
                                                icon={Icon::Search}
                                                value={(*inputtext).clone()}
                                                placeholder="Search for a package purl"
                                                onchange={on_inputtext_change}
                                                autofocus=true
                                            />
                                        </TextInputGroup>
                                    </FlexItem>

                                    <FlexItem>
                                        <Button
                                            variant={ButtonVariant::Primary}
                                            label="Search"
                                            onclick={on_searchbtn_click}
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
