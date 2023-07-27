use biscuit::Empty;
use chrono::Duration;
use openid::{
    validation::{validate_token_exp, validate_token_issuer},
    Claims, Client, CompactJson, Configurable, Jws, Provider,
};

pub type AccessToken<T> = Jws<T, Empty>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Common(#[from] openid::error::Error),
    #[error("Missing audience - expected: {expected}, actual: {actual}")]
    MissingAudience { expected: String, actual: String },
}

/// This is "fork" of the original [`Client::validate_token`] function, but implemented for
/// validating access tokens.
pub fn validate_token<C: CompactJson + Claims, P: Provider + Configurable>(
    client: &Client<P, C>,
    token: &AccessToken<C>,
    audience: Option<&str>,
    max_age: Option<&Duration>,
) -> Result<(), Error> {
    let claims = token.payload().map_err(openid::error::Error::Jose)?;
    let config = client.config();

    validate_token_issuer(claims, config)?;
    validate_token_exp(claims, max_age)?;
    validate_token_aud(claims, audience)?;

    Ok(())
}

pub fn validate_token_aud<C: Claims>(claims: &C, aud: Option<&str>) -> Result<(), Error> {
    let aud = match aud {
        Some(aud) => aud,
        None => return Ok(()),
    };

    if !claims.aud().contains(aud) {
        return Err(Error::MissingAudience {
            expected: aud.to_string(),
            actual: claims
                .aud()
                .iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .join(", "),
        });
    }

    Ok(())
}
