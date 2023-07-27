use gloo_storage::Storage;
use patternfly_yew::prelude::*;
use yew::function_component;
pub use yew::prelude::*;

pub const THEME_SETTINGS_KEY: &str = "chicken-theme-settings";

#[derive(Clone, Debug, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ThemeSettings {
    pub dark: bool,
}

#[derive(Clone, PartialEq)]
pub struct ThemeContext {
    pub settings: UseStateHandle<ThemeSettings>,
}

fn apply_theme(dark: bool) {
    log::info!("Apply theme - dark: {dark}");
    match dark {
        true => {
            let _ = gloo_utils::document_element().class_list().add_1("pf-v5-theme-dark");
        }
        false => {
            let _ = gloo_utils::document_element().class_list().remove_1("pf-v5-theme-dark");
        }
    }
}

#[function_component(Themed)]
pub fn themed(props: &ChildrenProperties) -> Html {
    let settings =
        use_state_eq::<ThemeSettings, _>(|| gloo_storage::LocalStorage::get(THEME_SETTINGS_KEY).unwrap_or_default());

    use_effect_with_deps(|dark| apply_theme(*dark), settings.dark);

    let context = ThemeContext { settings };

    html!(
        <ContextProvider<ThemeContext> {context}>
            { for props.children.iter() }
        </ContextProvider<ThemeContext>>
    )
}

#[function_component(DarkModeSwitch)]
pub fn dark_mode_switch() -> Html {
    let context = use_context::<ThemeContext>();

    let onchange = use_callback(
        |dark, context| {
            if let Some(context) = context {
                let new_state = ThemeSettings { dark };
                let _ = gloo_storage::LocalStorage::set(THEME_SETTINGS_KEY, &new_state);
                context.settings.set(new_state);
            }
        },
        context.clone(),
    );

    match context {
        Some(context) => {
            html!(<Switch checked={context.settings.dark} {onchange} label="Dark Theme" />)
        }
        None => {
            html!(<Switch label="Dark Theme" disabled=true />)
        }
    }
}

/// Drop down switch entry for dark mode
#[function_component(DarkModeEntry)]
pub fn dark_mode_entry() -> Html {
    html!(
        <div class="pf-v5-c-menu__list-item">
            <div
                class="pf-v5-c-menu__item"
                role="menuitem"
            >
                <DarkModeSwitch/>
            </div>
        </div>
    )
}
