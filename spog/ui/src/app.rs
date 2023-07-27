use crate::{
    components::{backend::Backend, error::Error, theme::Themed},
    console::Console,
    hooks::use_backend,
    pages::AppRoute,
};
use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_nested_router::prelude::*;
use yew_oauth2::{openid::*, prelude::*};

const DEFAULT_BACKEND_URL: &str = "/.well-known/chicken/backend.json";

#[function_component(Application)]
pub fn app() -> Html {
    html!(
        <Themed>
            <ToastViewer>
                <Backend
                    bootstrap_url={DEFAULT_BACKEND_URL}
                >
                    <ApplicationWithBackend />
                </Backend>
            </ToastViewer>
        </Themed>
    )
}

#[function_component(ApplicationWithBackend)]
fn application_with_backend() -> Html {
    let backend = use_backend();

    let config = Config {
        client_id: backend.endpoints.oidc.client_id.clone(),
        issuer_url: backend.endpoints.oidc.issuer.clone(),
        additional: Additional {
            /*
            Set the after logout URL to a public URL. Otherwise, the SSO server will redirect
            back to the current page, which is detected as a new session, and will try to login
            again, if the page requires this.
            */
            after_logout_url: Some(backend.endpoints.oidc.after_logout.clone()),
            ..Default::default()
        },
    };

    html!(
        // as the backdrop viewer might host content which makes use of the router, the
        // router must also wrap the backdrop viewer
        <Router<AppRoute>>
            <BackdropViewer>
                <OAuth2
                    {config}
                    scopes={backend.endpoints.oidc.scopes.clone()}
                >
                    <OAuth2Configured>
                        <Console />
                    </OAuth2Configured>
                </OAuth2>
            </BackdropViewer>
        </Router<AppRoute>>
    )
}

#[function_component(OAuth2Configured)]
pub fn oauth_configured(props: &ChildrenProperties) -> Html {
    let auth = use_context::<OAuth2Context>();

    match auth {
        None => html!(<Error err="Missing OAuth2 context"/>),
        Some(OAuth2Context::Failed(err)) => {
            html!(<Error {err}/>)
        }
        Some(_) => html!({ for props.children.iter() }),
    }
}
