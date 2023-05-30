use sikula::prelude::*;

// TODO: reconsider using scoped/primary for some fields, like status and severity
#[derive(Clone, Debug, PartialEq, Eq, Search)]
pub enum Vulnerabilities<'a> {
    #[search(default)]
    Id(Primary<'a>),
    #[search(default)]
    Cve(Primary<'a>),
    #[search(default)]
    Title(Primary<'a>),
    #[search(default)]
    Description(Primary<'a>),
    #[search(default)]
    Status(Primary<'a>),
    #[search(default)]
    Severity(Primary<'a>),

    Final,
    Critical,
    High,
    Medium,
    Low,
}
