use crate::{components::backend::Backend, console::Console, pages::AppRoute};
use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_nested_router::prelude::*;

const DEFAULT_BACKEND_URL: &str = "/.well-known/chicken/backend.json";

#[function_component(Application)]
pub fn app() -> Html {
    html!(
        <ToastViewer>
            <Backend
                bootstrap_url={DEFAULT_BACKEND_URL}
            >
                // as the backdrop viewer might host content which makes use of the router, the
                // router must also wrap the backdrop viewer
                <Router<AppRoute>>
                    <BackdropViewer>
                        <Console />
                    </BackdropViewer>
                </Router<AppRoute>>
            </Backend>
        </ToastViewer>
    )
}
