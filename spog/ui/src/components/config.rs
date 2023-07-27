use std::rc::Rc;

use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;
use yew_oauth2::hook::use_latest_access_token;

use crate::backend::ConfigService;
use crate::components::error::Error;
use crate::hooks::use_backend;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct ConfigurationProperties {
    #[prop_or_default]
    pub children: Children,
}

#[function_component(Configuration)]
pub fn configuration(props: &ConfigurationProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let config = use_async_with_cloned_deps(
        |backend| async {
            ConfigService::new(backend, access_token)
                .get_config()
                .await
                .map(Rc::new)
        },
        backend,
    );

    match &*config {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(),
        UseAsyncState::Ready(Err(err)) => html!(
            <Error err={err.clone()}/>
        ),
        UseAsyncState::Ready(Ok(config)) => html!(
            <ContextProvider<Rc<spog_model::config::Configuration>> context={config.clone()}>
                { for props.children.iter() }
            </ContextProvider<Rc<spog_model::config::Configuration>>>
        ),
    }
}
