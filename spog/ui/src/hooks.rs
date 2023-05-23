use crate::backend::Backend;
use std::rc::Rc;
use yew::prelude::*;

/// Get the backend instance. **Panics** if called from a component not nested somewhere under
/// the [`crate::components::backend::Backend`] component.
#[hook]
pub fn use_backend() -> Rc<Backend> {
    use_context::<Rc<Backend>>().expect("Must be called from a component wrapped in a 'Backend' component")
}
