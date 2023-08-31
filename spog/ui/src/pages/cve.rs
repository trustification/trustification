use crate::{
    backend::CveService,
    components::{async_state_renderer::async_content, common::PageHeading},
    hooks::use_backend,
    pages::AppRoute,
};
use patternfly_yew::prelude::*;
use spog_model::prelude::CveDetails;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::use_async_with_cloned_deps;
use yew_nested_router::prelude::*;
use yew_oauth2::hook::use_latest_access_token;

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

#[derive(PartialEq, Properties)]
pub struct ResultViewProperties {
    pub id: String,
}

#[function_component(ResultView)]
fn result_view(props: &ResultViewProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let state = use_async_with_cloned_deps(
        move |id| async move {
            let service = CveService::new(backend.clone(), access_token.clone());
            service.get(&id).await.map(Rc::new).map_err(|err| err.to_string())
        },
        props.id.clone(),
    );

    html!(
        <>
            <PageHeading>{&props.id}</PageHeading>
            <PageSection>
            {
                async_content(&*state, |state| html!(<ResultContent state={state.clone()} />))
            }
            </PageSection>
        </>
    )
}

#[derive(PartialEq, Properties)]
pub struct ResultContentProperties {
    state: Rc<CveDetails>,
}

#[function_component(ResultContent)]
fn result_content(props: &ResultContentProperties) -> Html {
    html!()
}

#[function_component(SearchView)]
fn search_view() -> Html {
    let text = use_state_eq(String::new);
    let onchange = use_callback(|value, text| text.set(value), text.clone());

    let router = use_router::<AppRoute>();

    let submit_cb = use_callback(
        move |(), text| {
            if let Some(router) = &router {
                router.push(AppRoute::Cve { id: (**text).clone() });
            }
        },
        text.clone(),
    );
    let onclick = (*use_memo(|cb| cb.reform(|_: MouseEvent| ()), submit_cb.clone())).clone();
    let onsubmit = (*use_memo(|cb| cb.reform(|_: SubmitEvent| ()), submit_cb)).clone();

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
