use std::str::FromStr;

use spog_model::vuln::Cvss3;
use yew::html::IntoPropValue;

#[derive(Clone, Debug, PartialEq)]
pub struct Cvss {
    pub score: f32,
    pub status: String,
}

#[derive(Copy, Clone, PartialEq, Eq, Ord, PartialOrd)]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl TryFrom<Cvss3> for Cvss {
    type Error = <f32 as FromStr>::Err;

    fn try_from(value: Cvss3) -> Result<Self, Self::Error> {
        Ok(Self {
            score: value.score.parse()?,
            status: value.status,
        })
    }
}

impl IntoPropValue<Cvss> for &Cvss3 {
    fn into_prop_value(self) -> Cvss {
        Cvss::from_or_critical(self)
    }
}

impl Cvss {
    pub fn from_or_critical(cvss: &Cvss3) -> Self {
        Self {
            score: cvss.score.parse().unwrap_or(10.0),
            status: cvss.status.clone(),
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
