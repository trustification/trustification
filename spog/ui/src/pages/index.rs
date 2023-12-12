use crate::{
    analytics::{ActionAnalytics, AnalyticEvents, ObjectNameAnalytics},
    pages::search,
};
use patternfly_yew::prelude::*;
use search::search_input::Search;
use spog_ui_common::components::SafeHtml;
use spog_ui_navigation::AppRoute;
use spog_ui_utils::{analytics::use_analytics, config::use_config};
use yew::prelude::*;
use yew_nested_router::prelude::*;

#[function_component(Index)]
pub fn index() -> Html {
    let config = use_config();
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
                                        <GridItem offset={[2]} cols={[4]}>
                                            <Search {onchange} />
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

                    <SafeHtml html={config.landing_page.after_outer_content.clone()} />

                </Grid>

            </PageSection>

            <SafeHtml html={config.landing_page.footer_content.clone()} />

        </>
    )
}
