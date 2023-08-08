use std::str::FromStr;

use spog_model::vuln::Cvss3;
use yew::{html::IntoPropValue, prelude::*};

#[derive(Clone, Debug, PartialEq)]
pub struct Cvss {
    pub score: f32,
}

#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl FromStr for Severity {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "none" => Self::None,
            "low" => Self::Low,
            "medium" => Self::Medium,
            "high" => Self::High,
            "critical" => Self::Critical,
            _ => return Err(()),
        })
    }
}

impl Severity {
    pub fn into_html(self) -> Html {
        let icon = |class: Classes| html!(<i class={classes!(class, "fa", "fa-shield-halved")}></i>);

        html!(
            <span class={classes!("tc-c-severity")}> {
                match self {
                    Self::None => icon(classes!("tc-m-severity-none")),
                    Self::Low => icon(classes!("tc-m-severity-low")),
                    Self::Medium => icon(classes!("tc-m-severity-moderate")),
                    Self::High => icon(classes!("tc-m-severity-important")),
                    Self::Critical => icon(classes!("tc-m-severity-critical")),
                }
            } </span>
        )
    }
}

impl From<Severity> for Html {
    fn from(value: Severity) -> Self {
        value.into_html()
    }
}

impl TryFrom<Cvss3> for Cvss {
    type Error = <f32 as FromStr>::Err;

    fn try_from(value: Cvss3) -> Result<Self, Self::Error> {
        Ok(Self {
            score: value.score.parse()?,
        })
    }
}

impl IntoPropValue<Cvss> for &Cvss3 {
    fn into_prop_value(self) -> Cvss {
        Cvss::from_or_critical(self)
    }
}

impl IntoPropValue<Cvss> for &cvss::v3::Base {
    fn into_prop_value(self) -> Cvss {
        Cvss {
            score: self.score().value() as f32,
        }
    }
}

impl Cvss {
    pub fn from_or_critical(cvss: &Cvss3) -> Self {
        Self {
            score: cvss.score.parse().unwrap_or(10.0),
        }
    }

    pub fn to_severity(&self) -> Severity {
        // according to: https://nvd.nist.gov/vuln-metrics/cvss
        if self.score >= 9.0 {
            Severity::Critical
        } else if self.score >= 7.0 {
            Severity::High
        } else if self.score >= 4.0 {
            Severity::Medium
        } else if self.score >= 0.1 {
            Severity::Low
        } else {
            Severity::None
        }
    }
}
