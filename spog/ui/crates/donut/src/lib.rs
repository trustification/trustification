use gloo_utils::format::JsValueSerdeExt;
use serde_json::Value;
use wasm_bindgen::prelude::*;
use yew::prelude::*;

#[wasm_bindgen(module = "/js/main.js")]
extern "C" {

    #[wasm_bindgen(js_name = "ChartDonutRenderer")]
    pub fn create(reference: &web_sys::Node, opts: &JsValue);

    #[wasm_bindgen(js_name = "SbomStackChartRenderer")]
    pub fn create_sbom_stack_chart_renderer(reference: &web_sys::Node, opts: &JsValue);

}

pub fn create_donut(node: &NodeRef, options: &JsValue) {
    if let Some(node) = node.get() {
        create(&node, options);
    }
}

pub fn create_sbom_stack_chart(node: &NodeRef, options: &JsValue) {
    if let Some(node) = node.get() {
        create_sbom_stack_chart_renderer(&node, options);
    }
}

#[derive(PartialEq, Properties)]
pub struct DonutProperties {
    pub options: Value,

    #[prop_or_default]
    pub labels: Option<Callback<Value, String>>,

    #[prop_or_default]
    pub style: Option<AttrValue>,
}

#[function_component(Donut)]
pub fn donut(props: &DonutProperties) -> Html {
    let node = use_node_ref();

    let labels = use_memo(props.labels.clone(), |labels| {
        labels.clone().map(|labels| {
            Closure::<dyn Fn(JsValue) -> String>::new(move |value: JsValue| {
                if let Ok(value) = value.into_serde::<Value>() {
                    labels.emit(value)
                } else {
                    "".to_string()
                }
            })
        })
    });

    use_effect_with((node.clone(), props.options.clone()), move |(node, options)| {
        if let Ok(options) = JsValue::from_serde(options) {
            if let Some(labels) = labels.as_ref() {
                let _ = js_sys::Reflect::set(&options, &JsValue::from_str("labels"), labels.as_ref());
            }
            create_donut(node, &options);
        }
    });

    html!(<div style={props.style.clone()} ref={node}></div>)
}

#[derive(PartialEq, Properties)]
pub struct SbomStackChartProperties {
    pub sboms: Value,

    #[prop_or_default]
    pub style: Option<AttrValue>,
}

#[function_component(SbomStackChart)]
pub fn sbom_stack_chart(props: &SbomStackChartProperties) -> Html {
    let node = use_node_ref();

    use_effect_with((node.clone(), props.sboms.clone()), move |(node, sboms)| {
        if let Ok(sboms) = JsValue::from_serde(sboms) {
            create_sbom_stack_chart(node, &sboms);
        }
    });

    html!(<div style={props.style.clone()} ref={node}></div>)
}

#[cfg(test)]
mod test {

    use super::*;
    use serde_json::json;

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
