use sikula::prelude::*;

#[derive(Clone, Debug, PartialEq, Search)]
pub enum Packages<'a> {
    #[search(default)]
    Dependent(Primary<'a>),
    #[search(default)]
    PackageName(Primary<'a>),
    #[search(default)]
    Purl(Primary<'a>),
    #[search(default)]
    Type(Primary<'a>),
    #[search(default)]
    Namespace(Primary<'a>),
    #[search(default)]
    Name(Primary<'a>),
    #[search(default)]
    Version(Primary<'a>),
    #[search(default)]
    Description(Primary<'a>),
    #[search(default)]
    Digest(Primary<'a>),
    #[search(default)]
    License(Primary<'a>),
    #[search(default)]
    Supplier(Primary<'a>),
    #[search(default)]
    Qualifier(Primary<'a>),
    Application,
    Library,
    Framework,
    Container,
    OperatingSystem,
    Device,
    Firmware,
    File,
}
