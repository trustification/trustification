
use serde::Deserialize;

#[derive(Deserialize)]
pub enum PackageManager {
    Maven,
    Npm,
    Gradle,
    Pip,
    Gomodules,
}

impl TryFrom<&str> for PackageManager {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "maven" => Ok(Self::Maven),
            "npm" => Ok(Self::Npm),
            "gradle" => Ok(Self::Gradle),
            "pip" => Ok(Self::Pip),
            "gomodules" => Ok(Self::Gomodules),
            _ => Err(())
        }
    }
}