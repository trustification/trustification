mod advisories;
mod products;

use advisories::RelatedAdvisories;
use patternfly_yew::prelude::*;
use products::RelatedProducts;
use spog_model::prelude::CveDetails;
use spog_ui_backend::{use_backend, CveService};
use spog_ui_components::{async_state_renderer::async_content, common::PageHeading, time::Date};
use std::rc::Rc;
use v11y_model::ScoreType;
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
            <GridItem cols={[12]}>
                <CveDetailsView details={props.details.clone()} />
            </GridItem>
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

#[derive(PartialEq, Properties)]
pub struct CveDetailsViewProperties {
    pub details: Rc<CveDetails>,
}

#[function_component(CveDetailsView)]
pub fn cve_details(props: &CveDetailsViewProperties) -> Html {
    props
        .details
        .details
        .iter()
        .map(|details| {
            html!(
                <Card title={html!(<Title>{ details.origin.clone() }</Title>)}>
                    <CardBody>
                        <DescriptionList>
                            if !details.summary.is_empty() {
                                <DescriptionGroup term="Summary">{ details.summary.clone() }</DescriptionGroup>
                            }
                            if !details.details.is_empty() {
                                <DescriptionGroup term="Details">{ details.details.clone() }</DescriptionGroup>
                            }
                            <DescriptionGroup term="Published"><Date timestamp={details.published} /></DescriptionGroup>
                            if let Some(withdrawn) = details.withdrawn {
                                <DescriptionGroup term="Published"><Date timestamp={withdrawn} /></DescriptionGroup>
                            }
                            if let Some(cvss3) = details.severities.iter().find(|score| score.r#type == ScoreType::Cvss3) {
                                <DescriptionGroup term="Score"></DescriptionGroup>
                            }
                        </DescriptionList>
                    </CardBody>
                </Card>
            )
        })
        .collect()
}
