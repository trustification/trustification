mod package_info;
mod related_products;
mod vulnerabilities;

use package_info::PackageAdditionalInfo;
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use related_products::RelatedProducts;
use spog_ui_backend::{use_backend, PackageInfoService};
use spog_ui_components::async_state_renderer::async_content;
use spog_ui_utils::config::use_config;
use std::{rc::Rc, str::FromStr};
use vulnerabilities::Vulnerabilities;
use yew::prelude::*;
use yew_more_hooks::prelude::{use_async_with_cloned_deps, use_page_state};
use yew_oauth2::prelude::use_latest_access_token;

#[derive(PartialEq, Properties)]
pub struct ResultViewProperties {
    pub id: String,
}

#[function_component(ResultView)]
pub fn result_view(props: &ResultViewProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let config = use_config();

    let package = {
        let backend = backend.clone();
        let access_token = access_token.clone();
        use_async_with_cloned_deps(
            move |id| async move {
                let service = PackageInfoService::new(backend.clone(), access_token.clone());
                service.get(&id).await.map(Rc::new).map_err(|err| err.to_string())
            },
            props.id.clone(),
        )
    };

    let related_products_details = {
        let backend = backend.clone();
        let access_token = access_token.clone();
        use_async_with_cloned_deps(
            move |id| async move {
                let service = PackageInfoService::new(backend.clone(), access_token.clone());
                service
                    .get_related_products(&id)
                    .await
                    .map(Rc::new)
                    .map_err(|err| err.to_string())
            },
            props.id.clone(),
        )
    };

    #[derive(Copy, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    enum TabIndex {
        Vulnerabilities,
        Products,
        PackageInfo,
    }

    #[derive(Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    struct PageState {
        tab: TabIndex,
    }

    let page_state = use_page_state(|| PageState {
        tab: TabIndex::Vulnerabilities,
    });

    let onselect = use_callback(page_state.clone(), |index, state| {
        state.modify(|state| state.tab = index);
    });

    let page_heading = use_memo(props.id.clone(), |id| match PackageUrl::from_str(id) {
        Ok(purl) => {
            let title = match purl.namespace() {
                Some(namespace) => match purl.ty() {
                    "maven" => format!("{}:{}", namespace, purl.name()),
                    _ => format!("{}/{}", namespace, purl.name()),
                },
                None => purl.name().to_string(),
            };

            let version = purl
                .version()
                .map_or(html!(<p></p>), |v| html!(<p>{ format!("Version: {v}") }</p>));

            let qualifiers =
                html!({ for purl.qualifiers().iter().map(|(k,v)| html!(<Label label={format!("{k}={v}")} />)) });

            html_nested!(
                <PageSection variant={PageSectionVariant::Light} >
                    <Content>
                        <Title>{title}</Title>
                        <Split gutter=true>
                            <SplitItem>{version}</SplitItem>
                            <SplitItem>{qualifiers}</SplitItem>
                        </Split>
                    </Content>
                </PageSection>
            )
        }
        Err(_) => html_nested!(
            <PageSection variant={PageSectionVariant::Light} >
                <Content><Title>{ props.id.clone() }</Title></Content>
            </PageSection>
        ),
    });

    html!(
        <>
            {(*page_heading).clone()}
            <PageSection>
                <Tabs<TabIndex> r#box=true selected={page_state.tab} {onselect}>
                    <Tab<TabIndex> index={TabIndex::Vulnerabilities} title="Vulnerabilities">
                        { async_content(&*package, |package| html!(<Vulnerabilities {package} />)) }
                    </Tab<TabIndex>>
                    <Tab<TabIndex> index={TabIndex::Products} title="Products using package">
                        { async_content(&*related_products_details, |related_products_details| html!(<RelatedProducts {related_products_details} />)) }
                    </Tab<TabIndex>>
                    { for config.features.additional_package_information.then(|| html_nested!(
                        <Tab<TabIndex> index={TabIndex::PackageInfo} title="Package additional info">
                            <PackageAdditionalInfo package_id={props.id.clone()} />
                        </Tab<TabIndex>>
                    )) }
                </Tabs<TabIndex>>
            </PageSection>
        </>
    )
}
