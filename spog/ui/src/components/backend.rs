use std::rc::Rc;

use web_sys::RequestCache;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;

use crate::{backend::Endpoints, components::error::Error};

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct BackendProperties {
    #[prop_or_default]
    pub children: Children,
    pub bootstrap_url: String,
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

            let endpoints: Endpoints = response
                .json()
                .await
                .map_err(|err| format!("Failed to decode backend information: {err}"))?;

            log::info!("Found: {endpoints:?}");

            Ok::<_, String>(crate::backend::Backend { endpoints })
        },
        UseAsyncOptions::enable_auto(),
    );

    match &*backend {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(),
        UseAsyncState::Ready(Err(err)) => html!(
            <Error err={err.clone()}/>
        ),
        UseAsyncState::Ready(Ok(backend)) => html!(
            <ContextProvider<Rc<crate::backend::Backend>> context={Rc::new(backend.clone())}>
                { for props.children.iter() }
            </ContextProvider<Rc<crate::backend::Backend>>>
        ),
    }
}
