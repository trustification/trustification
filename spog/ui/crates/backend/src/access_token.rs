use reqwest::header;
use url::{form_urlencoded, Url};
use yew_oauth2::context::LatestAccessToken;

pub trait ApplyAccessToken: Sized {
    fn access_token(self, access_token: &Option<String>) -> Self {
        if let Some(access_token) = access_token.as_ref() {
            self.apply_access_token(access_token)
        } else {
            self
        }
    }

    fn latest_access_token(self, access_token: &Option<LatestAccessToken>) -> Self {
        if let Some(access_token) = access_token.as_ref().and_then(|l| l.access_token()) {
            self.apply_access_token(&access_token)
        } else {
            self
        }
    }

    fn apply_access_token(self, access_token: &str) -> Self;
}

impl<'a, T: form_urlencoded::Target> ApplyAccessToken for &mut form_urlencoded::Serializer<'a, T> {
    fn apply_access_token(self, access_token: &str) -> Self {
        self.append_pair("token", access_token)
    }
}

impl ApplyAccessToken for Url {
    fn apply_access_token(mut self, access_token: &str) -> Self {
        self.query_pairs_mut().apply_access_token(access_token).finish();
        self
    }
}

impl ApplyAccessToken for reqwest::RequestBuilder {
    fn apply_access_token(self, access_token: &str) -> Self {
        self.bearer_auth(access_token)
    }
}

impl ApplyAccessToken for gloo_net::http::RequestBuilder {
    fn apply_access_token(self, access_token: &str) -> Self {
        self.header(header::AUTHORIZATION.as_str(), &format!("Bearer {access_token}"))
    }
}
