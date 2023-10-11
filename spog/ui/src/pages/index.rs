use patternfly_yew::prelude::*;
use spog_ui_common::components::SafeHtml;
use spog_ui_navigation::AppRoute;
use spog_ui_utils::config::use_config;
use yew::prelude::*;
use yew_nested_router::prelude::*;

#[function_component(Index)]
pub fn index() -> Html {
    let config = use_config();

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
    let onsubmit = use_callback((router.clone(), text.clone()), |_, (router, terms)| {
        if let Some(router) = router {
            router.push(AppRoute::Search {
                terms: (**terms).clone(),
            });
        }
    });

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

                                    <Bullseye>
                                        <Flex>
                                            <FlexItem>
                                                <TextInputGroup style="--pf-v5-c-text-input-group__text-input--MinWidth: 64ch;">
                                                    <TextInputGroupMain
                                                        id="search_terms"
                                                        icon={Icon::Search}
                                                        value={(*text).clone()}
                                                        placeholder="Search for an SBOM, advisory, or CVE"
                                                        {onchange}
                                                        autofocus=true
                                                    />
                                                </TextInputGroup>
                                            </FlexItem>

                                            <FlexItem>
                                                <Button
                                                    id="search"
                                                    variant={ButtonVariant::Primary}
                                                    label="Search"
                                                    {onclick}
                                                />
                                            </FlexItem>
                                        </Flex>
                                    </Bullseye>
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
