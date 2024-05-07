use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct ReportProperties {
    pub data: Rc<String>,
}

#[function_component(Report)]
pub fn report(props: &ReportProperties) -> Html {
    html!(
        <>
            <iframe
                class="tc-c-crda-report-viewer"
                srcdoc={(*props.data).clone()}
            />
        </>
    )
}
