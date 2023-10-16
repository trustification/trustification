mod advisories;
mod packages;
mod products;

use advisories::RelatedAdvisories;
use cve::published::Metric;
use patternfly_yew::prelude::*;
use products::RelatedProducts;
use spog_model::prelude::CveDetails;
use spog_ui_backend::{use_backend, CveService, SearchParameters, VexService};
use spog_ui_components::cvss::Cvss3Label;
use spog_ui_components::markdown::Markdown;
use spog_ui_components::{async_state_renderer::async_content, time::Date};
use std::rc::Rc;
use std::str::FromStr;
use yew::prelude::*;
use yew_more_hooks::hooks::use_page_state;
use yew_more_hooks::{hooks::use_async_with_cloned_deps, prelude::UseAsyncState};
use yew_oauth2::hook::use_latest_access_token;

#[derive(PartialEq, Properties)]
pub struct ResultViewProperties {
    /// the CVE id
    pub id: String,
}

#[function_component(ResultView)]
pub fn result_view(props: &ResultViewProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let details = {
        let backend = backend.clone();
        let access_token = access_token.clone();
        use_async_with_cloned_deps(
            move |id| async move {
                let service = CveService::new(backend.clone(), access_token.clone());
                service.get(&id).await.map(Rc::new).map_err(|err| err.to_string())
            },
            props.id.clone(),
        )
    };

    let products = {
        let backend = backend.clone();
        let access_token = access_token.clone();
        use_async_with_cloned_deps(
            move |id| async move {
                let service = CveService::new(backend.clone(), access_token.clone());
                service
                    .get_related_products(&id)
                    .await
                    .map(Rc::new)
                    .map_err(|err| err.to_string())
            },
            props.id.clone(),
        )
    };

    let advisories = {
        let backend = backend.clone();
        let access_token = access_token.clone();
        use_async_with_cloned_deps(
            |id| async move {
                let service = VexService::new(backend.clone(), access_token.clone());
                service
                    .search_advisories(&format!(r#"cve:{id}"#), &SearchParameters::default())
                    .await
                    .map(|r| {
                        let mut related = r.result;
                        related.sort_unstable_by(|a, b| a.id.cmp(&b.id));
                        Rc::new(related)
                    })
                    .map_err(|err| err.to_string())
            },
            props.id.clone(),
        )
    };

    #[derive(Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    enum TabIndex {
        Products,
        Advisories,
    }

    #[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct PageState {
        tab: TabIndex,
    }

    let page_state = use_page_state(|| PageState {
        tab: TabIndex::Products,
    });

    let onselect = use_callback(page_state.clone(), |index, state| {
        state.modify(|state| state.tab = index);
    });

    html!(
        <>
            <PageSection variant={PageSectionVariant::Light} >
                <Content>
                    <Title>
                        {props.id.clone()} { " "}
                        if let UseAsyncState::Ready(Ok(details)) = &*details {{
                            match &**details {
                                cve::Cve::Published(published) => cvss3(&published.containers.cna.metrics),
                                cve::Cve::Rejected(_rejected) => html!(<Label label="Rejected" color={Color::Grey} />),
                            }
                        }}
                    </Title>
                    if let UseAsyncState::Ready(Ok(details)) = &*details {
                        { cve_title(details) }
                    }
                </Content>

                <div class="pf-v5-u-my-md"></div>

                { async_content(&*details, |details| html!(<CveDetailsView details={details.clone()} />)) }
            </PageSection>

            <PageSection>
                <Tabs<TabIndex> r#box=true selected={page_state.tab} {onselect}>
                    <Tab<TabIndex> index={TabIndex::Products} title="Related Products">
                        { async_content(&*products, |products| html!(<RelatedProducts cve_details={products} />)) }
                    </Tab<TabIndex>>
                    <Tab<TabIndex> index={TabIndex::Advisories} title="Related Advisories">
                        { async_content(&*advisories, |advisories| html!(<RelatedAdvisories {advisories} />)) }
                    </Tab<TabIndex>>
                </Tabs<TabIndex>>
            </PageSection>
        </>
    )
}

// Result content

#[derive(PartialEq, Properties)]
pub struct ResultContentProperties {
    details: Rc<CveDetails>,
}

fn cve_title(cve: &cve::Cve) -> Html {
    if let cve::Cve::Published(details) = cve {
        html!(<p>{ details.containers.cna.title.clone() }</p>)
    } else {
        html!()
    }
}

fn cvss3(metrics: &[Metric]) -> Html {
    for m in metrics {
        if let Some(cvss) = m
            .cvss_v3_1
            .as_ref()
            .or(m.cvss_v3_0.as_ref())
            .and_then(|cvss| cvss["vectorString"].as_str())
            .and_then(|cvss| cvss::v3::Base::from_str(cvss).ok())
        {
            return html!(<Cvss3Label {cvss}/>);
        }
    }
    html!()
}

#[derive(PartialEq, Properties)]
pub struct CveDetailsViewProperties {
    pub details: Rc<cve::Cve>,
}

#[function_component(CveDetailsView)]
pub fn cve_details(props: &CveDetailsViewProperties) -> Html {
    html!(
        <Grid gutter=true> {

            match &*props.details {
                cve::Cve::Published(details) => {
                    html!(
                        <>
                            <GridItem cols={[6.lg(), 8.md(), 12.all()]}>
                                <Content>
                                    { for details.containers.cna.descriptions.iter().map(|desc|{
                                        html!(
                                            <div lang={desc.language.clone()}>
                                                <Markdown content={Rc::new(desc.value.clone())} />
                                            </div>
                                        )
                                    })}
                                </Content>
                            </GridItem>

                            <GridItem cols={[12]}>
                                <DescriptionList auto_fit=true>
                                    if let Some(timestamp) = details.metadata.date_published {
                                        <DescriptionGroup term="Published date"><Date timestamp={timestamp.assume_utc()} /></DescriptionGroup>
                                    }
                                    if let Some(timestamp) = details.metadata.date_updated {
                                        <DescriptionGroup term="Last modified"><Date timestamp={timestamp.assume_utc()} /></DescriptionGroup>
                                    }
                                </DescriptionList>
                            </GridItem>
                        </>
                    )
                }
                cve::Cve::Rejected(details) => {
                    html!(
                        <>
                            <GridItem cols={[6.lg(), 8.md(), 12.all()]}>
                                <Content>
                                    { for details.containers.cna.rejected_reasons.iter().map(|desc|{
                                        html!(
                                            <div lang={desc.language.clone()}>
                                                <Markdown content={Rc::new(desc.value.clone())} />
                                            </div>
                                        )
                                    })}
                                </Content>
                            </GridItem>

                            <GridItem cols={[12]}>
                                <DescriptionList auto_fit=true>
                                    if let Some(timestamp) = details.metadata.date_published {
                                        <DescriptionGroup term="Published date"><Date timestamp={timestamp.assume_utc()} /></DescriptionGroup>
                                    }
                                    if let Some(timestamp) = details.metadata.date_updated {
                                        <DescriptionGroup term="Last modified"><Date timestamp={timestamp.assume_utc()} /></DescriptionGroup>
                                    }
                                    if let Some(timestamp) = details.metadata.date_rejected {
                                        <DescriptionGroup term="Rejection date"><Date timestamp={timestamp.assume_utc()} /></DescriptionGroup>
                                    }
                                </DescriptionList>
                            </GridItem>
                        </>
                    )
                }
            }

        } </Grid>
    )
}
