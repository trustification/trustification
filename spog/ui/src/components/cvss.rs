use crate::utils::cvss::{Cvss, Severity};
use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct CvssScorenProperties {
    pub cvss: Cvss,
}

#[function_component(CvssScore)]
pub fn cvss_information(props: &CvssScorenProperties) -> Html {
    let label = format!("{}", props.cvss.score);

    let (color, outline) = match props.cvss.to_severity() {
        Severity::None => (Color::Grey, true),
        Severity::Low => (Color::Orange, true),
        Severity::Medium => (Color::Orange, false),
        Severity::High => (Color::Red, false),
        Severity::Critical => (Color::Purple, false),
    };

    html!(
        <Label {label} {color} {outline}/>
    )
}
