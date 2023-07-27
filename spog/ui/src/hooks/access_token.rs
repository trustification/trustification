use yew::prelude::*;
use yew_oauth2::prelude::*;

#[hook]
pub fn use_access_token() -> Option<String> {
    use_auth_state().and_then(|ctx| ctx.access_token().map(|s| s.to_string()))
}
