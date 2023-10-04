use patternfly_yew::prelude::*;
use spog_ui_common::utils::cvss::{Cvss, Severity};
use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use yew::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct CvssScoreProperties {
    pub cvss: Cvss,
}

#[function_component(CvssScore)]
pub fn cvss_information(props: &CvssScoreProperties) -> Html {
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

#[derive(PartialEq, Properties)]
pub struct Cvss3Properties {
    pub cvss: cvss::v3::Base,
}

#[function_component(Cvss3)]
pub fn cvss3(props: &Cvss3Properties) -> Html {
    // TODO: add popover to show more details
    html!(
        <CvssScore cvss={&props.cvss} />
    )
}

#[derive(PartialEq, Properties)]
pub struct CvssMapProperties {
    pub map: HashMap<String, u64>,
}

#[function_component(CvssMap)]
pub fn cvss_map(props: &CvssMapProperties) -> Html {
    let map = use_memo(props.map.clone(), |map| {
        let mut count = 0;

        // convert to BTreeMap: parse, sort, and count
        let mut result: BTreeMap<Severity, u64> = BTreeMap::new();
        for (k, v) in map {
            let k = Severity::from_str(k).unwrap_or(Severity::Critical);
            count += *v;
            result.insert(k, *v);
        }

        html!(
            <Flex space_items={[SpaceItems::Small]}>
                <FlexItem>{ count }</FlexItem>
                <Raw>
                    <Divider r#type={DividerType::Hr} orientation={[DividerOrientation::Vertical]} />
                </Raw>
                <FlexItem>
                { for result.into_iter().rev().map(|(k, v)| { html!(
                    <> { k } { " "} { v } { " "} </>
                )})}
                </FlexItem>
            </Flex>
        )
    });

    (*map).clone()
}
