use patternfly_yew::prelude::*;
use spog_model::prelude::PackageDependencies;
use spog_ui_backend::{use_backend, PackageService};
use spog_ui_components::async_state_renderer::async_content;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::use_async_with_cloned_deps;
use yew_oauth2::prelude::use_latest_access_token;

#[derive(PartialEq, Properties)]
pub struct PackageAdditionalInfoProperties {
    pub package_id: String,
}

#[function_component(PackageAdditionalInfo)]
pub fn package_additional_info(props: &PackageAdditionalInfoProperties) -> Html {
    html!(
        <>
            <Card>
                <CardBody>
                    <Grid gutter=true>
                        <GridItem cols={[4]}>
                            <Card title={html!(<Title>{"Package versions discovered"}</Title>)}>
                                <CardBody>
                                    <RelatedVersions package_id={props.package_id.clone()}/>
                                </CardBody>
                            </Card>
                        </GridItem>
                        <GridItem cols={[8]}>
                            <Card title={html!(<Title>{"Package dependents"}</Title>)}>
                                <CardBody>
                                    <Tree package_id={props.package_id.clone()}/>
                                </CardBody>
                            </Card>
                        </GridItem>
                    </Grid>
                </CardBody>
            </Card>
        </>
    )
}

// related version

#[derive(PartialEq, Properties)]
pub struct RelatedVersionsProperties {
    pub package_id: String,
}

#[function_component(RelatedVersions)]
pub fn related_versions(props: &RelatedVersionsProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let state = use_async_with_cloned_deps(
        move |package_id| async move {
            let service = PackageService::new(backend.clone(), access_token.clone());
            service
                .related_packages(&package_id)
                .await
                .map(Rc::new)
                .map_err(|err| err.to_string())
        },
        props.package_id.clone(),
    );

    html!(
        <>
            {
                async_content(&*state, |state| html!(<RelatedVersionsResultContent related_packages={state.clone()} />))
            }
        </>
    )
}

#[derive(PartialEq, Properties)]
pub struct RelatedVersionsResultContentProperties {
    related_packages: Rc<PackageDependencies>,
}

#[function_component(RelatedVersionsResultContent)]
fn related_versions_result_content(props: &RelatedVersionsResultContentProperties) -> Html {
    html!(
        <Grid gutter=true>
            <List>
                {
                    for props.related_packages.iter().map(|item| {
                        html!(
                            <>{&item.purl}</>
                        )
                    })
                }
            </List>
        </Grid>
    )
}

// Tree

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
                async_content(&*state, |state| html!(<TreeResultContent dependents={state.clone()} />))
            }
        </>
    )
}

#[derive(PartialEq, Properties)]
pub struct TreeResultContentProperties {
    dependents: Rc<PackageDependencies>,
}

#[function_component(TreeResultContent)]
fn tree_result_content(props: &TreeResultContentProperties) -> Html {
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
