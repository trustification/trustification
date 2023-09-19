use crate::config::use_config;
use patternfly_yew::prelude::*;
use spog_ui_common::components::SafeHtml;
use yew::prelude::*;
use yew_consent::prelude::*;

#[derive(PartialEq, Properties)]
pub struct AskConsentProperties {}

#[function_component(AskConsent)]
pub fn ask_consent() -> Html {
    html!(
        // We require our own backdrop viewer here, as the modal will be opened on the backdrop
        // which must be wrapped by the consent component. The main application's backdrop isn't
        // available yet at this point.
        <BackdropViewer>
            <AskConsentModal />
        </BackdropViewer>
    )
}

#[hook]
pub fn use_consent_dialog<T>() -> Callback<T>
where
    T: 'static,
{
    let backdrop = use_backdrop();
    use_callback(
        |_, backdrop| {
            if let Some(backdrop) = &backdrop {
                backdrop.open(html!(
                    <Bullseye>
                        <ConsentModal can_close=true show_current=true />
                    </Bullseye>
                ));
            }
        },
        backdrop,
    )
}

#[function_component(AskConsentModal)]
fn ask_consent_modal() -> Html {
    let backdrop = use_backdrop();

    use_effect(|| {
        if let Some(backdrop) = backdrop {
            backdrop.open(html!(
                <Bullseye>
                    <ConsentModal can_close=false />
                </Bullseye>
            ));
        }
    });

    html!()
}

#[derive(PartialEq, Properties)]
pub struct ConsentModalProperties {
    #[prop_or(true)]
    can_close: bool,

    #[prop_or_default]
    show_current: bool,
}

#[function_component(ConsentModal)]
pub fn consent_modal(props: &ConsentModalProperties) -> Html {
    let config = use_config();
    let context = use_consent_context().expect("Should be wrapped by the Consent component");

    let onyes = use_callback(|_, consent| consent.set(ConsentState::Yes(())), context.clone());
    let onno = use_callback(|_, consent| consent.set(ConsentState::No), context.clone());

    let footer = html!(
        <>
            <Button variant={ButtonVariant::Primary} label={config.consent.action_yes.as_deref().unwrap_or("Allow").to_string()} onclick={onyes} />
            <Button variant={ButtonVariant::Secondary} label={config.consent.action_no.as_deref().unwrap_or("Deny").to_string()} onclick={onno} />
        </>
    );

    let state = match use_consent() {
        ConsentState::Yes(()) => "enabled",
        ConsentState::No => "disabled",
    };

    html!(
        <Modal
            show_close={props.can_close}
            disable_close_escape={!props.can_close}
            disable_close_click_outside={!props.can_close}
            title={config.consent.title.as_deref().unwrap_or("Tracking consent").to_string()}
            variant={ModalVariant::Medium}
            {footer}
        >
            <Content>
                <SafeHtml html={config.consent.description.as_deref().unwrap_or("We would like to track your behavior on this site.").to_string()} />
                if props.show_current {
                    <p> {"Current state: "} <i>{ state } </i> </p>
                }
            </Content>

        </Modal>
    )
}
