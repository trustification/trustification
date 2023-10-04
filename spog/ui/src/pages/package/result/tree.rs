use patternfly_yew::prelude::*;
use spog_model::prelude::PackageDependencies;
use spog_ui_backend::{use_backend, PackageService};
use spog_ui_components::async_state_renderer::async_content;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::use_async_with_cloned_deps;
use yew_oauth2::hook::use_latest_access_token;

#[derive(PartialEq, Properties)]
pub struct TreeProperties {
    pub package_id: String,
}

#[function_component(Tree)]
pub fn tree(props: &TreeProperties) -> Html {
    let expand = use_state(|| false);
    let onclick = {
        let expand = expand.clone();
        Callback::from(move |_| expand.set(!*expand))
    };

    html!(
        <div class="tc-package-tree">
            <Accordion >
                <AccordionItem title={props.package_id.clone()} {onclick} expanded={*expand}>
                    if *expand {
                        <TreeContent package_id={props.package_id.clone()} />
                    }
                </AccordionItem>
            </Accordion>
        </div>
    )
}

#[derive(PartialEq, Properties)]
pub struct TreeContentProperties {
    pub package_id: String,
}

#[function_component(TreeContent)]
pub fn tree_content(props: &TreeContentProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let state = use_async_with_cloned_deps(
        move |package_id| async move {
            let service = PackageService::new(backend.clone(), access_token.clone());
            service
                .dependents(&package_id)
                .await
                .map(Rc::new)
                .map_err(|err| err.to_string())
        },
        props.package_id.clone(),
    );

    html!(
        <>
            {
                async_content(&*state, |state| html!(<ResultContent dependents={state.clone()} />))
            }
        </>
    )
}

#[derive(PartialEq, Properties)]
pub struct ResultContentProperties {
    dependents: Rc<PackageDependencies>,
}

#[function_component(ResultContent)]
fn result_content(props: &ResultContentProperties) -> Html {
    html!(
        <>
            { for props.dependents
                .iter()
                .map(|e| {
                    html!(
                        <>
                            <Tree package_id={e.purl.clone()}/>
                        </>
                    )
                })
            }
            if props.dependents.len() == 0 {
                <span>{"No more children found, this is the root package"}</span>
            }
        </>
    )
}
