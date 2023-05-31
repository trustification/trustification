use crate::{
    about,
    backend::Endpoint,
    hooks::use_backend,
    pages::{self, AppRoute},
};
use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_nested_router::prelude::Switch as RouterSwitch;

#[function_component(Console)]
pub fn console() -> Html {
    let logo = html! (
        <Brand src="assets/images/chicken-svgrepo-com.svg" alt="Chicken Logo" />
    );

    let backend = use_backend();

    let sidebar = html_nested!(
        <PageSidebar>
            <Nav>
                <NavList>
                    <NavExpandable title="Home">
                        <NavRouterItem<AppRoute> to={AppRoute::Index}>{ "Overview" }</NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::Chicken}>{ "Chicken" }</NavRouterItem<AppRoute>>
                    </NavExpandable>
                    <NavExpandable title="Investigate">
                        <NavRouterItem<AppRoute> to={AppRoute::Package{package: Default::default()}} predicate={AppRoute::is_package}>{ "Packages" }</NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::Vulnerability{cve: Default::default()}} predicate={AppRoute::is_vulnerability}>{ "Vulnerabilities" }</NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::SBOM}>{ "Upload SBOM" }</NavRouterItem<AppRoute>>
                    </NavExpandable>
                    <NavExpandable title="Extend">
                        if let Ok(url) = backend.join(Endpoint::Api, "/swagger-ui/") {
                            <NavItem external=true target="_blank" to={url.to_string()}>{ "API" }</NavItem>
                        }
                    </NavExpandable>
                </NavList>
            </Nav>
        </PageSidebar>
    );

    let callback_github = use_open("https://github.com/xkcd-2347/chicken-coop", "_blank");

    let backdrop = use_backdrop();

    let callback_about = Callback::from(move |_| {
        if let Some(backdrop) = &backdrop {
            backdrop.open(html!(<about::About/>));
        }
    });

    let tools = html!(
        <Toolbar>
            <ToolbarItem>
                <Button icon={Icon::Github} onclick={callback_github}/>
            </ToolbarItem>
            <ToolbarItem>
                <AppLauncher
                    position={Position::Right}
                    toggle={Icon::QuestionCircle}
                >
                    <AppLauncherItem onclick={callback_about}>{ "About" }</AppLauncherItem>
                </AppLauncher>
            </ToolbarItem>
        </Toolbar>
    );

    html!(
        <Page {logo} {sidebar} {tools}>
            <RouterSwitch<AppRoute> {render}/>

            <PageSection variant={PageSectionVariant::Darker} fill={PageSectionFill::NoFill}>
                {"Copyright © 2023 Red Hat, Inc. and "} <a href="https://github.com/xkcd-2347" target="_blank"> {"The chickens"} </a> {"."}
            </PageSection>
        </Page>
    )
}

fn render(route: AppRoute) -> Html {
    match route {
        AppRoute::Index => html!(<pages::Index/>),
        AppRoute::Chicken => html!(<pages::Chicken/>),
        AppRoute::Package { package } => html!(<pages::Package {package}/>),
        AppRoute::Vulnerability { cve } => html!(<pages::Vulnerability {cve}/>),
        AppRoute::SBOM => html!(<pages::SBOM/>),
    }
}
