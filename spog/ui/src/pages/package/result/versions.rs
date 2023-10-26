use patternfly_yew::prelude::*;
use spog_model::prelude::PackageDependencies;
use spog_ui_backend::{use_backend, PackageService};
use spog_ui_components::async_state_renderer::async_content;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::use_async_with_cloned_deps;
use yew_oauth2::hook::use_latest_access_token;

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
                async_content(&*state, |state| html!(<ResultContent related_packages={state.clone()} />))
            }
        </>
    )
}

#[derive(PartialEq, Properties)]
pub struct ResultContentProperties {
    related_packages: Rc<PackageDependencies>,
}

#[function_component(ResultContent)]
fn result_content(props: &ResultContentProperties) -> Html {
    html!(
        <Grid gutter=true>
            <List>
                {
                    for props.related_packages.iter().map(|item| {
                        html_nested! (
                            <ListItem>{&item.purl}</ListItem>
                        )
                    })
                }
            </List>
        </Grid>
    )
}
