use spog_ui_backend::{use_backend, ConfigService};
use spog_ui_common::error::components::ApiError;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;
use yew_oauth2::hook::use_latest_access_token;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct ConfigurationProperties {
    #[prop_or_default]
    pub children: Children,
    #[prop_or_default]
    pub public: bool,
}

#[function_component(Configuration)]
pub fn configuration(props: &ConfigurationProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let config = use_async_with_cloned_deps(
        |(backend, public)| async move {
            ConfigService::new(backend, access_token)
                .get_config(public)
                .await
                .map(Rc::new)
        },
        (backend, props.public),
    );

    match &*config {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(),
        UseAsyncState::Ready(Err(err)) => html!(
            <ApiError error={err.clone()} message="Failed to load application configuration" />
        ),
        UseAsyncState::Ready(Ok(config)) => html!(
            <ContextProvider<Rc<spog_model::config::Configuration>> context={config.clone()}>
                { for props.children.iter() }
            </ContextProvider<Rc<spog_model::config::Configuration>>>
        ),
    }
}
