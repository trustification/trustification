mod auth;

use crate::{
    about,
    backend::Endpoint,
    components::{
        common::{ExternalLinkMarker, ExternalNavLink},
        config::Configuration,
        theme::DarkModeEntry,
    },
    hooks::{use_backend, use_config},
    pages::{self, AppRoute, View},
};
use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_nested_router::prelude::Switch as RouterSwitch;
use yew_oauth2::{openid::*, prelude::*};

#[function_component(Console)]
pub fn console() -> Html {
    html!(
        <RouterSwitch<AppRoute> {render} default={html!(<pages::NotFound />)}/>
    )
}

fn brand() -> Html {
    html! (
        <MastheadBrand>
            <Brand
                src="assets/images/chicken-svgrepo-com.svg"
                alt="Logo"
                style={r#"
                    --pf-v5-c-brand--Height: var(--pf-v5-c-page__header-brand-link--c-brand--MaxHeight);
                "#}
            >
                <BrandSource srcset="assets/images/chicken-svgrepo-com.svg" />
            </Brand>
        </MastheadBrand>
    )
}

#[function_component(AuthenticatedPage)]
fn authenticated_page(props: &ChildrenProperties) -> Html {
    let brand = brand();

    let backend = use_backend();
    let config = use_config();

    let sidebar = html_nested!(
        <PageSidebar>
            <Nav>
                <NavList>
                    <NavRouterItem<AppRoute> to={AppRoute::Index}>{ "Trusted Content" }</NavRouterItem<AppRoute>>
                    <NavExpandable title="Search">
                        <NavRouterItem<AppRoute> to={AppRoute::Package(Default::default())} predicate={AppRoute::is_package}>{ "Packages" }</NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::Advisory(Default::default())} predicate={AppRoute::is_advisory}>{ "Advisories" }</NavRouterItem<AppRoute>>
                    </NavExpandable>
                    <NavExpandable title="Extend">
                        if let Ok(url) = backend.join(Endpoint::Api, "/swagger-ui/") {
                            <ExternalNavLink href={url.to_string()}>{ "API" }</ExternalNavLink>
                        }
                        if let Ok(url) = backend.join(Endpoint::Bombastic, "/swagger-ui/") {
                            <ExternalNavLink href={url.to_string()}>{ "SBOM API" }</ExternalNavLink>
                        }
                        if let Ok(url) = backend.join(Endpoint::Vexination, "/swagger-ui/") {
                            <ExternalNavLink href={url.to_string()}>{ "VEX API" }</ExternalNavLink>
                        }
                    </NavExpandable>
                </NavList>
            </Nav>
        </PageSidebar>
    );

    let callback_github = use_open("https://github.com/trustification/trustification", "_blank");

    let backdrop = use_backdrop();

    let callback_about = use_callback(
        move |_, ()| {
            if let Some(backdrop) = &backdrop {
                backdrop.open(html!(<about::About/>));
            }
        },
        (),
    );

    let auth = use_auth_state();
    let auth = use_memo(auth::from_auth, auth);

    let agent = use_auth_agent().expect("Requires OAuth2Context component in parent hierarchy");
    let onlogout = use_callback(
        move |_, _| {
            if let Err(err) = agent.logout() {
                log::warn!("Failed to logout: {err}");
            }
        },
        (),
    );

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
                        <ListDivider/>
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
            { for props.children.iter() }
        </Page>
    )
}

/// a non-authenticated page
#[function_component(NonAuthenticatedPage)]
fn non_authenticated_page(props: &ChildrenProperties) -> Html {
    let brand = brand();
    html!(
        <Page {brand}>
            { for props.children.iter() }
        </Page>
    )
}

fn render(route: AppRoute) -> Html {
    let content = match route {
        AppRoute::NotLoggedIn => return html!(<NonAuthenticatedPage><pages::NotLoggedIn/></NonAuthenticatedPage>),

        AppRoute::Index => html!(<pages::Index/>),
        AppRoute::Chicken => html!(<pages::Chicken/>),
        AppRoute::Scanner => html!(<pages::Scanner/>),

        AppRoute::Package(View::Search { query }) => html!(<pages::Package {query} />),
        AppRoute::Package(View::Content { id }) => html!(<pages::SBOM {id} />),
        AppRoute::Advisory(View::Search { query }) => html!(<pages::Advisory {query} />),
        AppRoute::Advisory(View::Content { id }) => html!(<pages::VEX {id} />),
    };

    html!(
        <RouterRedirect<AppRoute> logout={AppRoute::NotLoggedIn}>
            <Configuration>
                <AuthenticatedPage>
                    {content}
                </AuthenticatedPage>
            </Configuration>
        </RouterRedirect<AppRoute>>
    )
}
