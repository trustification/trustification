use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_oauth2::prelude::*;

pub struct FromAuth {
    pub avatar: Html,
    pub account_url: Option<String>,
    pub name: String,
    pub username: String,
}

pub fn claims(auth: &Option<OAuth2Context>) -> Option<&Claims> {
    auth.as_ref().and_then(|auth| auth.claims())
}

pub fn from_auth(auth: &Option<OAuth2Context>) -> FromAuth {
    let (_email, account_url, username, name) = match claims(auth) {
        Some(claims) => {
            let account_url = {
                let mut issuer = claims.issuer().url().clone();
                if let Ok(mut paths) = issuer
                    .path_segments_mut()
                    .map_err(|_| anyhow::anyhow!("Failed to modify path"))
                {
                    paths.push("account");
                }
                issuer.to_string()
            };

            let username = claims
                .preferred_username()
                .map(|s| s.as_ref())
                .unwrap_or_else(|| claims.subject().as_str())
                .to_string();

            let name = claims
                .name()
                .and_then(|name| name.get(None))
                .map(|s| s.to_string())
                .unwrap_or_else(|| username.clone());

            (claims.email(), Some(account_url), username, name)
        }
        None => (None, None, String::default(), String::default()),
    };

    // TODO: for now use the default, consider using the profile image
    let src = "assets/images/img_avatar.svg".to_string();

    FromAuth {
        avatar: html!(<Avatar {src} alt="avatar" size={AvatarSize::Small} />),
        account_url,
        name,
        username,
    }
}
