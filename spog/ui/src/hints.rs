use gloo_storage::Storage;
use strum::VariantNames;

#[derive(Copy, Clone, PartialEq, Eq, strum::AsRefStr, strum::Display, strum::EnumVariantNames)]
pub enum Hints {
    #[strum(serialize = "hint.scanner.welcome")]
    ScannerWelcome,
}

/// Clears all hints
pub fn clear_hints() {
    for hint in Hints::VARIANTS {
        gloo_storage::LocalStorage::delete(hint);
    }
}
