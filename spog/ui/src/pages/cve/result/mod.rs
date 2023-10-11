mod advisories;
mod products;

use advisories::RelatedAdvisories;
use patternfly_yew::prelude::*;
use products::RelatedProducts;
use spog_ui_backend::{use_backend, CveService, SearchParameters, VexService};
use spog_ui_components::{async_state_renderer::async_content, time::Date};
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::use_async_with_cloned_deps;
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
        let _backend = backend.clone();
        let _access_token = access_token.clone();
        use_async_with_cloned_deps(
            move |_id| async move { Ok::<_, String>(Rc::new(vec!["Product A".to_string(), "Product B".to_string()])) },
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

    #[derive(Copy, Clone, PartialEq, Eq)]
    enum TabIndex {
        Products,
        Advisories,
    }

    let tab = use_state_eq(|| TabIndex::Products);
    let onselect = use_callback(tab.clone(), |index, selected| selected.set(index));

    html!(
        <>
            <PageSection sticky={vec![PageSectionSticky::Top]} variant={PageSectionVariant::Light} >
                <Content>
                    <Title>{props.id.clone()}</Title>
                </Content>
                { async_content(&*details, |details| html!(<CveDetailsView details={details.clone()} />)) }
            </PageSection>

            <PageSection>
                <Tabs<TabIndex> r#box=true selected={*tab} {onselect}>
                    <Tab<TabIndex> index={TabIndex::Products} title="Related Products">
                        { async_content(&*products, |products| html!(<RelatedProducts {products} />)) }
                    </Tab<TabIndex>>
                    <Tab<TabIndex> index={TabIndex::Advisories} title="Related Advisories">
                        { async_content(&*advisories, |advisories| html!(<RelatedAdvisories {advisories} />)) }
                    </Tab<TabIndex>>
                </Tabs<TabIndex>>
            </PageSection>
        </>
    )
}

#[derive(PartialEq, Properties)]
pub struct CveDetailsViewProperties {
    pub details: Rc<cve::Cve>,
}

#[function_component(CveDetailsView)]
pub fn cve_details(props: &CveDetailsViewProperties) -> Html {
    match &*props.details {
        cve::Cve::Published(details) => {
            html!(
                <DescriptionList>
                    if let Some(title) = &details.containers.cna.title {
                        <DescriptionGroup term="Title">{ title.clone() }</DescriptionGroup>
                    }
                    <DescriptionGroup term="Descriptions">
                        { for details.containers.cna.descriptions.iter().map(|desc|{
                            html!({ desc.value.clone() })
                        })}
                    </DescriptionGroup>
                    if let Some(timestamp) = details.metadata.date_published {
                        <DescriptionGroup term="Published"><Date timestamp={timestamp.assume_utc()} /></DescriptionGroup>
                    }
                </DescriptionList>
            )
        }
        cve::Cve::Rejected(details) => {
            html!()
        }
    }
}
