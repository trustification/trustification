use crate::{about, pages};
use patternfly_yew::prelude::*;
use spog_ui_backend::{use_backend, Endpoint};
use spog_ui_common::utils::auth::from_auth;
use spog_ui_components::{
    common::{ExternalLinkMarker, ExternalNavLink},
    theme::DarkModeEntry,
};
use spog_ui_navigation::{AppRoute, View};
use spog_ui_utils::{analytics::*, config::*, hints::*};
use yew::prelude::*;
use yew_consent::hook::use_consent_context;
use yew_more_hooks::prelude::*;
use yew_nested_router::prelude::Switch as RouterSwitch;
use yew_oauth2::{openid::*, prelude::*};

/// The main console component
#[function_component(Console)]
pub fn console() -> Html {
    let config = use_config();
    let render = move |route| render(route, &config);

    html!(<RouterSwitch<AppRoute> {render} default={html!(<pages::NotFound />)}/>)
}

#[function_component(Brand)]
fn brand() -> Html {
    let config = use_config();

    let src = config.global.brand_image_src();

    html! (
        <MastheadBrand>
            <patternfly_yew::prelude::Brand
                src={src.clone()}
                alt="Logo"
                style={r#"
                    --pf-v5-c-brand--Height: var(--pf-v5-c-page__header-brand-link--c-brand--MaxHeight);
                "#}
            >
                <BrandSource srcset={src} />
            </patternfly_yew::prelude::Brand>
        </MastheadBrand>
    )
}

#[function_component(AuthenticatedPage)]
fn authenticated_page(props: &ChildrenProperties) -> Html {
    let brand = html!(<Brand/>);

    let backend = use_backend();
    let config = use_config();

    let sidebar = html_nested!(
        <PageSidebar>
            <Nav>
                <NavList>
                    <NavRouterItem<AppRoute> to={AppRoute::Index}>{ "Home" }</NavRouterItem<AppRoute>>
                    if config.features.dedicated_search {
                        <NavExpandable expanded=true title="Search">
                            <NavRouterItem<AppRoute> to={AppRoute::Advisory(Default::default())} predicate={AppRoute::is_advisory}>{ "Advisories" }</NavRouterItem<AppRoute>>
                            <NavRouterItem<AppRoute> to={AppRoute::Sbom(Default::default())} predicate={AppRoute::is_sbom}>{ "SBOMs" }</NavRouterItem<AppRoute>>
                            <NavRouterItem<AppRoute> to={AppRoute::Cve(Default::default())} predicate={AppRoute::is_cve}>{ "CVEs" }</NavRouterItem<AppRoute>>
                            <NavRouterItem<AppRoute> to={AppRoute::Package{id: Default::default()}} predicate={AppRoute::is_package}>{ "Packages" }</NavRouterItem<AppRoute>>
                        </NavExpandable>
                    } else {
                        <NavRouterItem<AppRoute> to={AppRoute::Search{terms: String::new()}}>{ "Search" }</NavRouterItem<AppRoute>>
                    }
                    if config.features.scanner {
                        <NavRouterItem<AppRoute> to={AppRoute::Scanner}>{ "Scan SBOM" }</NavRouterItem<AppRoute>>
                    }
                    if config.features.extend_section {
                        <NavExpandable title="Extend">
                            if let Ok(url) = backend.join(Endpoint::Bombastic, "/swagger-ui/") {
                                <ExternalNavLink href={url.to_string()}>{ "SBOM API" }</ExternalNavLink>
                            }
                            if let Ok(url) = backend.join(Endpoint::Vexination, "/swagger-ui/") {
                                <ExternalNavLink href={url.to_string()}>{ "VEX API" }</ExternalNavLink>
                            }
                        </NavExpandable>
                    }
                    if let Some(url) = &config.global.support_url {
                        <ExternalNavLink href={url.to_string()}>{ "Support" }</ExternalNavLink>
                    }
                </NavList>
            </Nav>
        </PageSidebar>
    );

    let callback_github = use_open("https://github.com/trustification/trustification", "_blank");

    let support_case_url = &config.global.support_case_url.as_ref().map(|url| url.to_string());
    let open_support_case_page = use_callback(support_case_url.clone(), |_, support_case_url| {
        if let Some(support_case_url) = support_case_url {
            let _ = gloo_utils::window().open_with_url_and_target(support_case_url.as_str(), "_blank");
        }
    });

    let backdrop = use_backdrop();

    let callback_about = use_callback((), move |_, ()| {
        if let Some(backdrop) = &backdrop {
            backdrop.open(html!(<about::About/>));
        }
    });

    let auth = use_auth_state();
    let auth = use_memo(auth, from_auth);

    let agent = use_auth_agent().expect("Requires OAuth2Context component in parent hierarchy");
    let onlogout = use_callback((), move |_, _| {
        if let Err(err) = agent.logout() {
            log::warn!("Failed to logout: {err}");
        }
    });

    let onconsent = use_consent_dialog();
    let manage_consent = use_consent_context::<()>().is_some();

    let onclearhints = use_callback((), |_, _| clear_hints());

    let tools = html!(
        <Toolbar>
            <ToolbarContent>
                <ToolbarItem modifiers={[ToolbarElementModifier::Right]}>
                    <Button icon={Icon::Github} onclick={callback_github} variant={ButtonVariant::Plain} />
                    <Dropdown
                        position={Position::Right}
                        variant={MenuToggleVariant::Plain}
                        icon={Icon::QuestionCircle}
                    >
                        {
                            for config.global.documentation_url.as_ref().map(|url| html_nested!(
                                <MenuLink href={url.to_string()} target="_blank">
                                    { "Documentation" } <ExternalLinkMarker/>
                                </MenuLink>
                            ))
                        }
                        {
                            for config.global.support_case_url.as_ref().map(|_url| html_nested!(
                                <MenuAction onclick={open_support_case_page} >
                                    {"Open a support case"}
                                </MenuAction>
                            ))
                        }
                        <MenuAction onclick={callback_about}>
                            { "About" }
                        </MenuAction>
                    </Dropdown>
                </ToolbarItem>
                <ToolbarItem>
                    <Dropdown
                        position={Position::Right}
                        variant={MenuToggleVariant::Plain}
                        icon={auth.avatar.clone()}
                        text={auth.name.clone()}
                        disabled={auth.username.is_empty()}
                    >
                        { for auth.account_url.as_ref().map(|url| { html_nested!(
                            <MenuLink href={url.to_string()} target="_blank">
                                {"Account "} <ExternalLinkMarker/>
                            </MenuLink>)
                        }) }
                        <Raw>
                            <DarkModeEntry />
                        </Raw>
                        <MenuAction onclick={onclearhints}>
                            { "Clear hints" }
                        </MenuAction>
                        <ListDivider/>

                        { manage_consent.then(|| {
                            html_nested!(
                                <MenuAction onclick={onconsent}>
                                    { "User consent" }
                                </MenuAction>
                            )
                        }) }

                        <MenuAction onclick={onlogout}>
                            { "Logout" }
                        </MenuAction>
                    </Dropdown>
                </ToolbarItem>
            </ToolbarContent>
        </Toolbar>
    );

    html!(
        <Page {brand} {sidebar} {tools}>
            { props.children.clone() }
        </Page>
    )
}

/// a non-authenticated page
#[function_component(NonAuthenticatedPage)]
fn non_authenticated_page(props: &ChildrenProperties) -> Html {
    html!(
        <Page brand={html!(<Brand/>)}>
            { props.children.clone() }
        </Page>
    )
}

fn render(route: AppRoute, config: &spog_model::config::Configuration) -> Html {
    let content = match route {
        AppRoute::NotLoggedIn => return html!(<NonAuthenticatedPage><pages::NotLoggedIn/></NonAuthenticatedPage>),

        AppRoute::Index => html!(<pages::Index/>),
        AppRoute::Search { terms } => html!(<pages::Search {terms} />),

        AppRoute::Chicken => html!(<pages::Chicken/>),
        AppRoute::Scanner if config.features.scanner => html!(<pages::Scanner/>),

        AppRoute::Sbom(View::Search { query }) if config.features.dedicated_search => {
            html!(<pages::Sbom {query} />)
        }
        AppRoute::Sbom(View::Content { id }) if config.features.dedicated_search => html!(<pages::SBOM {id} />),
        AppRoute::Advisory(View::Search { query }) if config.features.dedicated_search => {
            html!(<pages::Advisory {query} />)
        }
        AppRoute::Advisory(View::Content { id }) if config.features.dedicated_search => html!(<pages::VEX {id} />),
        AppRoute::Cve(View::Search { query }) if config.features.dedicated_search => {
            html!(<pages::CveSearchPage {query} />)
        }
        AppRoute::Cve(View::Content { id }) if config.features.dedicated_search => {
            html!(<pages::Cve {id} />)
        }
        AppRoute::Package { id } if config.features.dedicated_search => {
            let id = match id.is_empty() {
                true => None,
                false => Some(id),
            };
            html!(<pages::Package {id} />)
        }

        _ => html!(<pages::NotFound />),
    };

    html!(
        <RouterRedirect<AppRoute> logout={AppRoute::NotLoggedIn}>
            <AuthenticatedPage>
                {content}
            </AuthenticatedPage>
        </RouterRedirect<AppRoute>>
    )
}
