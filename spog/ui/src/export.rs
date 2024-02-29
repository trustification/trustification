use wasm_bindgen::prelude::wasm_bindgen;
use wasm_bindgen::JsValue;

/// trigger the router to navigate to some targets
#[wasm_bindgen(js_name = spogNavigateTo)]
pub fn navigate_to(path: &str) {
    let _ = yew_nested_router::History::push_state(JsValue::null(), path);
}
