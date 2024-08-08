use std::rc::Rc;

use crate::{
    analytics::{ActionAnalytics, AnalyticEvents, ObjectNameAnalytics},
    pages::search,
};
use patternfly_yew::prelude::*;
use search::search_input::SearchInput;
use spog_ui_backend::{use_backend, DashboardService, SBOMService};
use spog_ui_common::{components::SafeHtml, error::components::Error};
use spog_ui_donut::SbomStackChart;
use spog_ui_navigation::{AppRoute, View};
use spog_ui_utils::{analytics::use_analytics, config::use_config_private};
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_nested_router::components::Link;
use yew_nested_router::prelude::*;
use yew_oauth2::hook::use_latest_access_token;

#[function_component(Index)]
pub fn index() -> Html {
    let config = use_config_private();
    let analytics = use_analytics();

    let text = use_state_eq(String::new);
    let onchange = use_callback(text.clone(), |new_text, text| text.set(new_text));

    let router = use_router::<AppRoute>();
    let onclick = use_callback((router.clone(), text.clone()), |_, (router, terms)| {
        if let Some(router) = router {
            router.push(AppRoute::Search {
                terms: (**terms).clone(),
            });
        }
    });
    let onsubmit = use_callback(
        (analytics.clone(), router.clone(), text.clone()),
        |_, (analytics, router, terms)| {
            analytics.track(AnalyticEvents {
                obj_name: ObjectNameAnalytics::HomePage,
                action: ActionAnalytics::Search((**terms).clone()),
            });

            if let Some(router) = router {
                router.push(AppRoute::Search {
                    terms: (**terms).clone(),
                });
            }
        },
    );

    html!(
        <>
            <SafeHtml html={config.landing_page.header_content.clone()} />

            <PageSection variant={PageSectionVariant::Default}>

                <Grid gutter=true>

                    <SafeHtml html={config.landing_page.before_outer_content.clone()} />

                    <GridItem cols={[12]}>
                        <Card>
                            <CardBody>
                                <SafeHtml html={config.landing_page.before_inner_content.clone()} />

                                <form {onsubmit}>
                                    // needed to trigger submit when pressing enter in the search field
                                    <input type="submit" hidden=true formmethod="dialog" />

                                    <Grid gutter=true>
                                        <GridItem offset={[4]} cols={[4]}>
                                            <SearchInput {onchange} autofocus=true />
                                        </GridItem>

                                        <GridItem cols={[1]}>
                                            <Button
                                                id="search"
                                                variant={ButtonVariant::Primary}
                                                label="Search"
                                                {onclick}
                                            />
                                        </GridItem>
                                    </Grid>

                                </form>
                                <SafeHtml html={config.landing_page.after_inner_content.clone()} />

                            </CardBody>
                        </Card>
                    </GridItem>

                    <GridItem cols={[12]}>
                        <Card>
                            <CardTitle><Title size={Size::Medium}>{"Your dashboard"}</Title></CardTitle>
                            <CardBody>
                                <Grid gutter=true>
                                    <GridItem cols={[6]}>
                                        <Stack gutter=true>
                                            <StackItem>
                                                {"Below is a summary of CVE status for your last 10 ingested SBOMs. You can click on the SBOM name or CVE severity number below to be taken to their respective details page. You can also select up to 4 SBOMs to watch, by default you will see the last 4 SBOMs you have uploaded."}
                                            </StackItem>
                                            <StackItem>
                                                <LastSbomsChart />
                                            </StackItem>
                                        </Stack>
                                    </GridItem>
                                    <GridItem cols={[6]}>
                                        <LastDataIngested />
                                    </GridItem>
                                </Grid>
                            </CardBody>
                        </Card>
                    </GridItem>

                    <SafeHtml html={config.landing_page.after_outer_content.clone()} />

                </Grid>

            </PageSection>

            <SafeHtml html={config.landing_page.footer_content.clone()} />

        </>
    )
}

#[function_component(LastSbomsChart)]
pub fn last_sboms_chart() -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let sboms = use_async_with_cloned_deps(
        |backend| async move {
            SBOMService::new(backend.clone(), access_token)
                .get_latest_with_vulns()
                .await
                .map(|result| serde_json::to_value(result).expect("Could not unparse latest sbom json"))
        },
        backend,
    );

    html!(
        <>
            {
                match &*sboms {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        </PageSection>
                    ),
                    UseAsyncState::Ready(Ok(value)) => html!(
                        <SbomStackChart sboms={value.clone()} style="height: 375px; width: 600px" />
                    ),
                    UseAsyncState::Ready(Err(_)) => html!(
                        <Error title="Error" message="Error while uploading the file" />
                    ),
                }
            }
        </>
    )
}

#[function_component(LastDataIngested)]
pub fn last_data_ingested() -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let summary = use_async_with_cloned_deps(
        |backend| async move {
            DashboardService::new(backend.clone(), access_token)
                .get_summary()
                .await
                .map(Rc::new)
        },
        backend,
    );

    html!(
        <>
            {
                match &*summary {
                    UseAsyncState::Pending | UseAsyncState::Processing => html!(
                        <PageSection fill={PageSectionFill::Fill}>
                            <Spinner />
                        </PageSection>
                    ),
                    UseAsyncState::Ready(Ok(value)) => html!(
                        <Grid>
                            <GridItem cols={[6]}>
                                <DescriptionList>
                                    <DescriptionGroup term="Last SBOM ingested">
                                        <Stack>
                                            <StackItem>
                                                {&value.sbom_summary.last_updated_date}
                                            </StackItem>
                                            <StackItem>
                                                if let Some(last_updated_sbom_id) = &value.sbom_summary.last_updated_sbom_id {
                                                    <Link<AppRoute> to={AppRoute::Sbom(View::Content {id: last_updated_sbom_id.clone()})} >
                                                        { &value.sbom_summary.last_updated_sbom_name }
                                                    </Link<AppRoute>>
                                                }
                                            </StackItem>
                                        </Stack>
                                    </DescriptionGroup>
                                    <DescriptionGroup term="Last Advisory ingested">
                                        <Stack>
                                            <StackItem>
                                                {&value.csaf_summary.last_updated_date}
                                            </StackItem>
                                            <StackItem>
                                                if let Some(last_updated_csaf_id) = &value.csaf_summary.last_updated_csaf_id {
                                                    <Link<AppRoute> to={AppRoute::Advisory(View::Content {id: last_updated_csaf_id.clone()})} >
                                                        { &value.csaf_summary.last_updated_csaf_name }
                                                    </Link<AppRoute>>
                                                }
                                            </StackItem>
                                        </Stack>
                                    </DescriptionGroup>
                                    <DescriptionGroup term="Last CVE ingested">
                                        <Stack>
                                            <StackItem>
                                                {&value.cve_summary.last_updated_date}
                                            </StackItem>
                                            <StackItem>
                                                if let Some(last_updated_cve) = &value.cve_summary.last_updated_cve {
                                                    <Link<AppRoute> to={AppRoute::Cve(View::Content {id: last_updated_cve.clone()})} >
                                                        { &value.cve_summary.last_updated_cve }
                                                    </Link<AppRoute>>
                                                }
                                            </StackItem>
                                        </Stack>
                                    </DescriptionGroup>
                                </DescriptionList>
                            </GridItem>
                            <GridItem cols={[6]}>
                                <DescriptionList>
                                    <DescriptionGroup term="Total SBOMs">
                                        {value.sbom_summary.total_sboms}
                                    </DescriptionGroup>
                                    <DescriptionGroup term="Total Advisories">
                                        {value.csaf_summary.total_csafs}
                                    </DescriptionGroup>
                                    <DescriptionGroup term="Total CVEs">
                                        {value.cve_summary.total_cves}
                                    </DescriptionGroup>
                                </DescriptionList>
                            </GridItem>
                        </Grid>
                    ),
                    UseAsyncState::Ready(Err(_)) => html!(
                        <Error title="Error" message="Error while uploading the file" />
                    ),
                }
            }
        </>
    )
}
