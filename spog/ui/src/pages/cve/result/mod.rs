mod advisories;
mod products;

use crate::{
    backend::CveService,
    components::{async_state_renderer::async_content, common::PageHeading},
    hooks::use_backend,
};
use advisories::RelatedAdvisories;
use patternfly_yew::prelude::*;
use products::RelatedProducts;
use spog_model::prelude::CveDetails;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::use_async_with_cloned_deps;
use yew_oauth2::hook::use_latest_access_token;

#[derive(PartialEq, Properties)]
pub struct ResultViewProperties {
    pub id: String,
}

#[function_component(ResultView)]
pub fn result_view(props: &ResultViewProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let state = use_async_with_cloned_deps(
        move |id| async move {
            let service = CveService::new(backend.clone(), access_token.clone());
            service.get(&id).await.map(Rc::new).map_err(|err| err.to_string())
        },
        props.id.clone(),
    );

    html!(
        <>
            <PageHeading>{&props.id}</PageHeading>
            <PageSection>
            {
                async_content(&*state, |state| html!(<ResultContent details={state.clone()} />))
            }
            </PageSection>
        </>
    )
}

#[derive(PartialEq, Properties)]
pub struct ResultContentProperties {
    details: Rc<CveDetails>,
}

#[function_component(ResultContent)]
fn result_content(props: &ResultContentProperties) -> Html {
    let advisories = use_memo(|details| details.advisories.clone(), props.details.clone());
    let products = use_memo(|details| details.products.clone(), props.details.clone());

    html!(
        <Grid gutter=true>
            <GridItem cols={[6]}>
                <Card title={html!(<Title>{"Related products"}</Title>)}>
                    <CardBody>
                        <RelatedProducts {products} />
                    </CardBody>
                </Card>
            </GridItem>
            <GridItem cols={[6]}>
                <Card title={html!(<Title>{"Related advisories"}</Title>)}>
                    <CardBody>
                        <RelatedAdvisories {advisories} />
                    </CardBody>
                </Card>
            </GridItem>
        </Grid>
    )
}
