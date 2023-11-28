use spog_model::config::Configuration;
use std::rc::Rc;
use yew::prelude::*;

/// Get the frontend configuration. **Panics** if called from a component not nested somewhere under
/// the [`spog_ui_utils::components::backend::Configuration`] component.
#[hook]
pub fn use_config() -> Rc<Configuration> {
    use_context::<Rc<Configuration>>().expect("Must be called from a component wrapped in a 'Configuration' component")
}
