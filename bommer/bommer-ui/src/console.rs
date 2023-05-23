use patternfly_yew::prelude::*;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_nested_router::prelude::Switch as RouterSwitch;

use crate::about;
use crate::pages::{self, AppRoute};

#[function_component(Console)]
pub fn console() -> Html {
    let logo = html! (
        <Brand src="assets/images/crystal-ball-svgrepo-com.svg" alt="SPOG Logo" />
    );

    let sidebar = html_nested!(
        <PageSidebar>
            <Nav>
                <NavList>
                    <NavExpandable title="Home">
                        <NavRouterItem<AppRoute> to={AppRoute::Index}>{ "Overview" }</NavRouterItem<AppRoute>>
                        <NavRouterItem<AppRoute> to={AppRoute::ByNamespace{namespace: Default::default()}} predicate={AppRoute::is_by_namespace}>{ "Workload" }</NavRouterItem<AppRoute>>
                    </NavExpandable>
                </NavList>
            </Nav>
        </PageSidebar>
    );

    let callback_github = use_open("https://github.com/xkcd-2347/bommer", "_blank");

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
        AppRoute::ByNamespace { namespace } => {
            html!(<pages::Workload {namespace}/>)
        }
    }
}
