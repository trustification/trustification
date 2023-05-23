use patternfly_yew::prelude::*;
use std::rc::Rc;
use url::Url;
use web_sys::RequestCache;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct BackendProperties {
    #[prop_or_default]
    pub children: Children,
    pub bootstrap_url: String,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct BackendEndpoint {
    pub url: Url,
}

#[function_component(Backend)]
pub fn backend(props: &BackendProperties) -> Html {
    let backend = use_async_with_options(
        async {
            log::info!("Discovering backend...");
            // we cannot use reqwest here, as we might need to do a relative lookup, based on the
            // current web page. Which is something that Url (which is used by reqwest) doesn't
            // support. But gloo_net does.
            let response = gloo_net::http::Request::get("/endpoints/backend.json")
                .cache(RequestCache::NoCache)
                .send()
                .await
                .map_err(|err| format!("Failed to load backend information: {err}"))?;

            let endpoint: BackendEndpoint = response
                .json()
                .await
                .map_err(|err| format!("Failed to decode backend information: {err}"))?;

            log::info!("Found: {endpoint:?}");

            Ok::<_, String>(crate::backend::Backend { url: endpoint.url })
        },
        UseAsyncOptions::enable_auto(),
    );

    match &*backend {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(),
        UseAsyncState::Ready(Err(err)) => html!(
            <Bullseye>
                <Grid gutter=true>
                    <GridItem offset={[2]} cols={[2]}>
                        <img src="assets/images/chicken-svgrepo-com.svg" style="transform: scaleY(-1);"/>
                    </GridItem>
                    <GridItem cols={[6]}>
                        <Title>{"Failure"}</Title>
                        { format!("Failed to initialize backend: {err}") }
                    </GridItem>
                </Grid>

            </Bullseye>
        ),
        UseAsyncState::Ready(Ok(backend)) => html!(
            <ContextProvider<Rc<crate::backend::Backend>> context={Rc::new(backend.clone())}>
                { for props.children.iter() }
            </ContextProvider<Rc<crate::backend::Backend>>>
        ),
    }
}
