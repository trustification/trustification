use std::rc::Rc;

use patternfly_yew::prelude::*;
use spog_ui_backend::use_backend;
use spog_ui_common::error::components::ApiError;
use yew::prelude::*;
use yew_more_hooks::hooks::*;
use yew_oauth2::hook::use_latest_access_token;

use crate::{common::NotFound, sbom::report_viewer::ReportViewwer};

#[derive(PartialEq, Properties)]
pub struct ReportButtonProperties {
    pub id: String,
}

#[function_component(ReportButton)]
pub fn report_button(props: &ReportButtonProperties) -> Html {
    let backdropper = use_backdrop().expect("Requires BackdropViewer in its hierarchy");

    let onclick = use_callback((props.id.clone(), backdropper.clone()), |_, (id, backdropper)| {
        backdropper.open(Backdrop::new(html!(
            <Bullseye>
                <Modal
                    title = {"Report"}
                    variant = { ModalVariant::Large }
                >
                    <ReportModal id={id.to_string()}/>
                </Modal>
            </Bullseye>
        )));
    });

    html!(
        <Button
            icon={Icon::Eye}
            variant={ButtonVariant::Plain}
            {onclick}
        />
    )
}

#[derive(PartialEq, Properties)]
pub struct ReportModalProperties {
    pub id: String,
}

#[function_component(ReportModal)]
pub fn report_modal(props: &ReportModalProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let sbom = use_async_with_cloned_deps(
        |(id, backend)| async move {
            spog_ui_backend::SBOMService::new(backend.clone(), access_token)
                .get(id)
                .await
        },
        (props.id.clone(), backend),
    );

    let content = match &*sbom {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(<Spinner />),
        UseAsyncState::Ready(Ok(None)) => html!(<NotFound/>),
        UseAsyncState::Ready(Ok(Some(data))) => html!(
            <div style="height: 700px">
                <ReportViewwer raw={Rc::new((*data).clone())} />
            </div>
        ),
        UseAsyncState::Ready(Err(err)) => html!(<ApiError error={err.clone()} />),
    };

    html!(
        <>
            {content}
        </>
    )
}
