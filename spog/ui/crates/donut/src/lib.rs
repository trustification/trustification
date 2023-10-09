use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/js/main.js")]
extern "C" {

    #[wasm_bindgen(js_name = "createPopper")]
    pub fn create_popper(reference: &web_sys::Node, popper: &web_sys::Node, opts: &JsValue) -> Instance;

    #[derive(Clone, Debug)]
    pub type Instance;

    #[wasm_bindgen(method)]
    pub fn destroy(this: &Instance);

    #[wasm_bindgen(method)]
    pub async fn update(this: &Instance);

    #[wasm_bindgen(method, js_name = "forceUpdate")]
    pub fn force_update(this: &Instance);

    #[wasm_bindgen(method, getter)]
    pub fn state(this: &Instance) -> State;
}
