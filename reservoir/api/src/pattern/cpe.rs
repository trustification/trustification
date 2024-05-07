use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub enum Part {
    Application,
    Hardware,
    OperatingSystem,
}

pub struct Version {
    version: String,
    update: Option<Update>,
}

impl Version {
    pub fn new<V: Into<String>>(version: V) -> Self {
        Self {
            version: version.into(),
            update: None,
        }
    }

    pub fn with_update(mut self, update: Update) -> Self {
        self.update.replace(update);
        self
    }
}

pub struct Update {
    update: String,
    edition: Option<String>,
}

impl Update {
    pub fn new<U: Into<String>>(update: U) -> Self {
        Self {
            update: update.into(),
            edition: None,
        }
    }

    pub fn with_edition<E: Into<String>>(mut self, edition: E) -> Self {
        self.edition.replace(edition.into());
        self
    }
}

pub struct CpePattern {
    part: Part,
    vendor: String,
    product: String,
    version: Option<Version>,
}

impl CpePattern {
    pub fn application<V: Into<String>, P: Into<String>>(vendor: V, product: P) -> Self {
        Self {
            part: Part::Application,
            vendor: vendor.into(),
            product: product.into(),
            version: None,
        }
    }

    pub fn hardware<V: Into<String>, P: Into<String>>(vendor: V, product: P) -> Self {
        Self {
            part: Part::Hardware,
            vendor: vendor.into(),
            product: product.into(),
            version: None,
        }
    }

    pub fn operating_system<V: Into<String>, P: Into<String>>(vendor: V, product: P) -> Self {
        Self {
            part: Part::OperatingSystem,
            vendor: vendor.into(),
            product: product.into(),
            version: None,
        }
    }

    pub fn with_version(mut self, version: Version) -> Self {
        self.version.replace(version);
        self
    }
}

#[cfg(test)]
mod test {
    use crate::pattern::cpe::CpePattern;

    #[test]
    pub fn construct_simple() {
        let _pattern = CpePattern::application("redhat", "rhel");
    }
}
