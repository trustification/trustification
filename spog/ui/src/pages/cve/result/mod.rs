mod advisories;
mod packages;
mod products;

use advisories::RelatedAdvisories;
use cve::published::Metric;
use patternfly_yew::prelude::*;
use products::RelatedProducts;
use spog_model::prelude::CveDetails;
use spog_ui_backend::{use_backend, CveService, SearchParameters, VexService};
use spog_ui_components::{
    async_state_renderer::async_content, common::Visible, cvss::Cvss3Label, editor::ReadonlyEditor, markdown::Markdown,
    time::Date,
};
use std::rc::Rc;
use std::str::FromStr;
use yew::prelude::*;
use yew_more_hooks::hooks::use_page_state;
use yew_more_hooks::{hooks::use_async_with_cloned_deps, prelude::UseAsyncState};
use yew_oauth2::hook::use_latest_access_token;

const CVE_DESCRIPTION_MAX_LENGTH: usize = 180;

fn truncate(s: &str, max_chars: usize) -> &str {
    match s.char_indices().nth(max_chars) {
        None => s,
        Some((idx, _)) => &s[..idx],
    }
}

#[derive(PartialEq, Properties)]
pub struct ResultViewProperties {
    /// the CVE id
    pub id: String,
}

#[function_component(ResultView)]
pub fn result_view(props: &ResultViewProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let cve_details = {
        let backend = backend.clone();
        let access_token = access_token.clone();
        use_async_with_cloned_deps(
            move |id| async move {
                let service = CveService::new(backend.clone(), access_token.clone());
                service
                    .get(&id)
                    .await
                    .map_err(|err| err.to_string())?
                    .map(|source| {
                        Ok::<_, String>((
                            Rc::new(serde_json::from_str::<cve::Cve>(&source).map_err(|err| err.to_string())?),
                            Rc::new(source),
                        ))
                    })
                    .transpose()
            },
            props.id.clone(),
        )
    };

    let related_products = {
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

    let related_advisories = {
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
        Source,
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
                        if let UseAsyncState::Ready(Ok(details)) = &*cve_details {{
                             match details.as_ref().map(|details| details.0.as_ref()) {
                                Some(cve::Cve::Published(published)) => cvss3(&published.containers.cna.metrics),
                                Some(cve::Cve::Rejected(_rejected)) => html!(<Label label="Rejected" color={Color::Grey} />),
                                None => html!(),
                            }
                        }}
                    </Title>
                    if let UseAsyncState::Ready(Ok(Some((details, _)))) = &*cve_details {
                        { cve_title(details) }
                    }
                </Content>

                <div class="pf-v5-u-my-md"></div>

                { async_content(&*cve_details, |details| html!(
                    if let Some((details, _)) = details.clone() {
                        <CveDetailsView {details} />
                    }
                )) }
            </PageSection>

            <PageSection class="pf-v5-u-pb-0">
                <Tabs<TabIndex> r#box=true selected={page_state.tab} {onselect} detached=true>
                    <Tab<TabIndex> index={TabIndex::Products} title="Related Products" />
                    <Tab<TabIndex> index={TabIndex::Advisories} title="Related Advisories" />
                    <Tab<TabIndex> index={TabIndex::Source} title="Source" />
                </Tabs<TabIndex>>
            </PageSection>

            <PageSection class="pf-v5-u-pt-0">
                <Visible visible={matches!(page_state.tab, TabIndex::Products)} >
                    { async_content(&*related_products, |products| html!(<RelatedProducts cve_details={products} />)) }
                </Visible>
                <Visible visible={matches!(page_state.tab, TabIndex::Advisories)} >
                    { async_content(&*related_advisories, |advisories| html!(<RelatedAdvisories {advisories} />)) }
                </Visible>
                <Visible visible={matches!(page_state.tab, TabIndex::Source)} style="height: 100%;">
                    { async_content(&*cve_details, |details| html!(
                        if let Some((_, content)) = details {
                            <ReadonlyEditor {content} />
                        }
                    )) }
                </Visible>
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
    let show_more = use_state_eq(|| false);

    let show_more_toggle = use_callback(show_more.clone(), |_, show_more| {
        let current = **show_more;
        show_more.set(!current);
    });

    html!(
        <Grid gutter=true> {
            match &*props.details {
                cve::Cve::Published(details) => {
                    html!(
                        <>
                            <GridItem cols={[6.lg(), 8.md(), 12.all()]}>
                                <Content>
                                    {
                                        if !*show_more && details.containers.cna.descriptions.iter()
                                            .map(|e| e.value.len())
                                            .sum::<usize>() > CVE_DESCRIPTION_MAX_LENGTH
                                        {
                                            html!(
                                                <>
                                                    {truncate(&details.containers.cna.descriptions[0].value, CVE_DESCRIPTION_MAX_LENGTH)}{"..."}
                                                    <Button variant={ButtonVariant::Link} onclick={show_more_toggle}>{ "More" }</Button>
                                                </>
                                            )
                                        } else {
                                            html!(
                                                <>
                                                    { for details.containers.cna.descriptions.iter().map(|desc|{
                                                        html!(
                                                            <div lang={desc.language.clone()}>
                                                                <Markdown content={Rc::new(desc.value.clone())} />
                                                            </div>
                                                        )
                                                    })}
                                                </>
                                            )
                                        }
                                    }
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
                                    {
                                        if !*show_more && details.containers.cna.rejected_reasons.iter()
                                            .map(|e| e.value.len())
                                            .sum::<usize>() > CVE_DESCRIPTION_MAX_LENGTH
                                        {
                                            html!(
                                                <>
                                                    {truncate(&details.containers.cna.rejected_reasons[0].value, CVE_DESCRIPTION_MAX_LENGTH)}{"..."}
                                                    <Button variant={ButtonVariant::Link} onclick={show_more_toggle}>{ "More" }</Button>
                                                </>
                                            )
                                        } else {
                                            html!(
                                                <>
                                                    { for details.containers.cna.rejected_reasons.iter().map(|desc|{
                                                        html!(
                                                            <div lang={desc.language.clone()}>
                                                                <Markdown content={Rc::new(desc.value.clone())} />
                                                            </div>
                                                        )
                                                    })}
                                                </>
                                            )
                                        }
                                    }
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
