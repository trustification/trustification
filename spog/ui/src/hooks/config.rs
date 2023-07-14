use std::rc::Rc;

use yew::prelude::*;

use spog_model::config::Configuration;

/// Get the frontend configuration. **Panics** if called from a component not nested somewhere under
/// the [`crate::components::backend::Configuration`] component.
#[hook]
pub fn use_config() -> Rc<Configuration> {
    use_context::<Rc<Configuration>>().expect("Must be called from a component wrapped in a 'Configuration' component")
}
