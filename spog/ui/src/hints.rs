use gloo_storage::Storage;
use strum::VariantNames;
use yew::html::IntoPropValue;

#[derive(Copy, Clone, PartialEq, Eq, strum::AsRefStr, strum::Display, strum::EnumVariantNames)]
pub enum Hints {
    #[strum(serialize = "hint.scanner.welcome")]
    ScannerWelcome,
}

impl IntoPropValue<String> for Hints {
    fn into_prop_value(self) -> String {
        self.to_string()
    }
}

/// Clears all hints
pub fn clear_hints() {
    for hint in Hints::VARIANTS {
        gloo_storage::LocalStorage::delete(hint);
    }
}
