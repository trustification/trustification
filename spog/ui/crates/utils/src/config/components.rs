use spog_model::config::PrivateConfiguration;
use spog_ui_backend::{use_backend, ConfigService};
use spog_ui_common::error::components::ApiError;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;
use yew_oauth2::hook::use_latest_access_token;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct PublicConfigurationComponentProperties {
    #[prop_or_default]
    pub children: Children,
}

#[function_component(PublicConfigurationComponent)]
pub fn public_configuration_component(props: &PublicConfigurationComponentProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let config = use_async_with_cloned_deps(
        |backend| async move {
            ConfigService::new(backend.clone(), access_token.clone())
                .get_config(true)
                .await
                .map(Rc::new)
        },
        backend,
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

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct PrivateConfigurationComponentProperties {
    #[prop_or_default]
    pub children: Children,
}

#[function_component(PrivateConfigurationComponent)]
pub fn private_configuration_component(props: &PrivateConfigurationComponentProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let config = use_async_with_cloned_deps(
        |backend| async move {
            ConfigService::new(backend.clone(), access_token.clone())
                .get_config(false)
                .await
                .map(|e| Rc::new(PrivateConfiguration(e)))
        },
        backend,
    );

    match &*config {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(),
        UseAsyncState::Ready(Err(err)) => html!(
            <ApiError error={err.clone()} message="Failed to load application configuration" />
        ),
        UseAsyncState::Ready(Ok(config)) => html!(
            <ContextProvider<Rc<spog_model::config::PrivateConfiguration>> context={config.clone()}>
                { for props.children.iter() }
            </ContextProvider<Rc<spog_model::config::PrivateConfiguration>>>
        ),
    }
}
