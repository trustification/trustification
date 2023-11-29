use gloo_history::History;
use wasm_bindgen::prelude::wasm_bindgen;

/// trigger the router to navigate to some targets
#[wasm_bindgen(js_name = spogNavigateTo)]
pub fn navigate_to(path: &str) {
    gloo_history::BrowserHistory::new().push(path)
}
