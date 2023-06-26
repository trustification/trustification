use sikula::prelude::*;

#[derive(Clone, Debug, PartialEq, Search)]
pub enum Packages<'a> {
    #[search(default)]
    Package(Primary<'a>),
    #[search]
    Type(Primary<'a>),
    #[search]
    Namespace(Primary<'a>),
    #[search]
    Version(Primary<'a>),
    #[search(default)]
    Description(Primary<'a>),
    #[search]
    Created(Ordered<time::OffsetDateTime>),
    #[search]
    Digest(Primary<'a>),
    #[search]
    License(Primary<'a>),
    #[search(scope)]
    Supplier(Primary<'a>),
    #[search]
    Qualifier(Qualified<'a, &'a str>),
    #[search]
    Dependency(Primary<'a>),
    Application,
    Library,
    Framework,
    Container,
    OperatingSystem,
    Device,
    Firmware,
    File,
}
