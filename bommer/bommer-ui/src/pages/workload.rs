use std::rc::Rc;

use bommer_api::data::{Event, Image, ImageRef};
use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_hooks::use_websocket;

use crate::backend::{self, IntoWs};
use crate::components::workload::WorkloadTable;
use crate::hooks::use_backend;

#[derive(Clone, Debug, PartialEq, Eq, Properties)]
pub struct WorkloadProperties {
    #[prop_or_default]
    pub namespace: String,
}

#[function_component(Workload)]
pub fn workload(props: &WorkloadProperties) -> Html {
    let backend = use_backend();

    let ws = use_websocket(
        backend
            .join(match props.namespace.is_empty() {
                true => "/api/v1/workload_stream".to_string(),
                false => format!("/api/v1/workload_stream/{}", props.namespace),
            })
            .unwrap()
            .into_ws()
            .to_string(),
    );

    let workload = use_state(|| Rc::new(backend::Workload::default()));

    {
        let workload = workload.clone();
        use_effect_with_deps(
            move |message| {
                if let Some(message) = &**message {
                    if let Ok(evt) = serde_json::from_str::<Event<ImageRef, Image>>(message) {
                        match evt {
                            Event::Added(image, state) | Event::Modified(image, state) => {
                                let mut s = (**workload).clone();
                                s.insert(image, state);
                                workload.set(Rc::new(s));
                            }
                            Event::Removed(image) => {
                                let mut s = (**workload).clone();
                                s.remove(&image);
                                workload.set(Rc::new(s));
                            }
                            Event::Restart(state) => {
                                workload.set(Rc::new(backend::Workload(state)));
                            }
                        }
                    }
                }

                || ()
            },
            ws.message,
        )
    };

    html!(
        <>
            <PageSection
                variant={PageSectionVariant::Light}
                shadow={PageSectionShadow::Bottom}
                fill=false
            >
                <Content>
                    <Title level={Level::H1}>{"Discovered Workload"}</Title>
                </Content>
            </PageSection>

            <PageSection variant={PageSectionVariant::Default} fill=true>
                <WorkloadTable workload={(*workload).clone()} />
            </PageSection>

        </>
    )
}
