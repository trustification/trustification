use gloo_utils::format::JsValueSerdeExt;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use yew::prelude::*;

#[wasm_bindgen(module = "/js/main.js")]
extern "C" {

    #[wasm_bindgen(js_name = "ChartDonutRenderer")]
    pub fn create(reference: &web_sys::Node, opts: &JsValue);

}

pub fn create_donut(node: &NodeRef, options: &Value) {
    if let Some(node) = node.get() {
        if let Ok(options) = JsValue::from_serde(options) {
            create(&node, &options);
        }
    }
}

#[derive(PartialEq, Properties)]
pub struct DonutProperties {
    pub options: Value,
}

#[function_component(Donut)]
pub fn donut(props: &DonutProperties) -> Html {
    let node = use_node_ref();

    use_effect_with((node.clone(), props.options.clone()), |(node, options)| {
        create_donut(node, options);
    });

    html!(<div ref={node}></div>)
}

#[cfg(test)]
mod test {

    use super::*;
    use serde_json::json;
    use yew::prelude::*;

    #[function_component(Example)]
    pub fn example() -> Html {
        let options = json!({
          "ariaDesc": "Average number of pets",
          "ariaTitle": "Donut chart example",
          "constrainToVisibleArea": true,
          "data": [
            { "x": "Cats", "y": 35 },
            { "x": "Dogs", "y": 55 },
            { "x": "Birds", "y": 10 },
          ],
          // "labels": ({ datum }) => `${datum.x}: ${datum.y}%`,
          "legendData": [{ "name": "Cats: 35" }, { "name": "Dogs: 55" }, { "name": "Birds: 10" }],
          "legendOrientation": "vertical",
          "legendPosition": "right",
          "name": "chart2",
          "padding": { "bottom": 20, "left": 20, "right": 140, "top": 20 },
          "subTitle": "Pets",
          "title": "100",
          "width": 350,
        });

        html!(
            <Donut {options} />
        )
    }
}
