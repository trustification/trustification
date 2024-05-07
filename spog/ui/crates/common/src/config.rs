use spog_model::config::{Configuration, PrivateConfiguration};
use std::rc::Rc;
use yew::prelude::*;

/// Get the frontend configuration. **Panics** if called from a component not nested somewhere under
/// the [`spog_ui_utils::components::backend::Configuration`] component.
#[hook]
pub fn use_config_public() -> Rc<Configuration> {
    use_context::<Rc<Configuration>>().expect("Must be called from a component wrapped in a 'Configuration' component")
}

/// Get the frontend configuration. **Panics** if called from a component not nested somewhere under
/// the [`spog_ui_utils::components::backend::Configuration`] component.
#[hook]
pub fn use_config_private() -> Rc<Configuration> {
    let config = use_context::<Rc<PrivateConfiguration>>()
        .expect("Must be called from a component wrapped in a 'PrivateConfiguration' component");
    Rc::new(config.0.clone())
}
