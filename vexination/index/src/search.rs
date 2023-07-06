use sikula::prelude::*;

// TODO: reconsider using scoped/primary for some fields, like status and severity
#[derive(Clone, Debug, PartialEq, Search)]
pub enum Vulnerabilities<'a> {
    #[search(default)]
    Id(Primary<'a>),
    #[search(default)]
    Cve(Primary<'a>),
    #[search(default)]
    Title(Primary<'a>),
    #[search(default)]
    Description(Primary<'a>),
    Status(&'a str),
    #[search]
    Severity(&'a str),
    Cvss(PartialOrdered<f64>),
    #[search(scope)]
    Package(Primary<'a>),
    #[search(scope)]
    Fixed(Primary<'a>),
    #[search(scope)]
    Affected(Primary<'a>),
    #[search]
    Initial(Ordered<time::OffsetDateTime>),
    #[search]
    Release(Ordered<time::OffsetDateTime>),
    #[search]
    Discovery(Ordered<time::OffsetDateTime>),
    Final,
    Critical,
    High,
    Medium,
    Low,
}
