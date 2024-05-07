use std::str::FromStr;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct SeverityProperties {
    pub severity: AttrValue,
}

#[function_component(Severity)]
pub fn severity(props: &SeverityProperties) -> Html {
    let severity_text = match RedHatSeverity::from_str(&props.severity) {
        Ok(severity) => {
            format!("{}", severity)
        }
        Err(_) => props.severity.clone().to_string(),
    };
    html!(
        <>
            <span class={classes!("tc-c-severity")}>
                <span class={classes!("tc-c-severity__icon")}>
                    { RedHatSeverity::from_str(&props.severity).map(Shield).ok() }
                </span>
                <span class={classes!("tc-c-severity__text")}>
                    { " " }
                    { &severity_text }
                </span>
            </span>
        </>
    )
}

/// Severity according to https://access.redhat.com/security/updates/classification
pub enum RedHatSeverity {
    Low,
    Moderate,
    Important,
    Critical,
}

pub struct Shield<T>(pub T);

impl From<Shield<RedHatSeverity>> for Html {
    fn from(value: Shield<RedHatSeverity>) -> Self {
        let icon = |class: Classes| html!(<i class={classes!(class, "fa", "fa-shield-halved")}></i>);

        match value.0 {
            RedHatSeverity::Low => icon(classes!("tc-m-severity-low")),
            RedHatSeverity::Moderate => icon(classes!("tc-m-severity-moderate")),
            RedHatSeverity::Important => icon(classes!("tc-m-severity-important")),
            RedHatSeverity::Critical => icon(classes!("tc-m-severity-critical")),
        }
    }
}

impl ToHtml for Shield<RedHatSeverity> {
    fn to_html(&self) -> Html {
        let icon = |class: Classes| html!(<i class={classes!(class, "fa", "fa-shield-halved")}></i>);

        match self.0 {
            RedHatSeverity::Low => icon(classes!("tc-m-severity-low")),
            RedHatSeverity::Moderate => icon(classes!("tc-m-severity-moderate")),
            RedHatSeverity::Important => icon(classes!("tc-m-severity-important")),
            RedHatSeverity::Critical => icon(classes!("tc-m-severity-critical")),
        }
    }
}

impl std::fmt::Display for RedHatSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Low => f.write_str("Low"),
            Self::Moderate => f.write_str("Moderate"),
            Self::Important => f.write_str("Important"),
            Self::Critical => f.write_str("Critical"),
        }
    }
}

impl FromStr for RedHatSeverity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_lowercase().as_str() {
            "low" => Self::Low,
            "moderate" => Self::Moderate,
            "important" => Self::Important,
            "critical" => Self::Critical,
            _ => return Err(()),
        })
    }
}
