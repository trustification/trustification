use crate::{components::backend::Backend, console::Console, pages::AppRoute};
use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_nested_router::prelude::*;

#[function_component(Application)]
pub fn app() -> Html {
    html!(
        <ToastViewer>
            <Backend>
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
