use yew::prelude::*;
use yew_oauth2::prelude::*;

/// Get an access token from the current authentication context
///
/// The function will always return a fresh token, it should not be stored. It also should not
/// be used as a dependency on other hooks or trigger re-renders.
#[hook]
pub fn use_access_token() -> Option<String> {
    use_auth_state().and_then(|ctx| ctx.access_token().map(|s| s.to_string()))
}
