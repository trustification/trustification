use anyhow::{bail, Context};
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use std::str::FromStr;
use yew::prelude::*;

const MSG_NOT_EMPTY: &str = "Must not be empty";
const DEFAULT_SEARCH: &str = "pkg:maven/io.quarkus/quarkus-core@2.16.2.Final?type=jar";

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct PackageLookupProperties {
    onchange: Callback<Option<PackageUrl<'static>>>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
enum EntryType {
    #[default]
    Input,
    #[allow(unused)]
    Area,
}

#[derive(Clone, Debug, PartialEq, Properties)]
struct SingleValueEntryProperties {
    onchange: Callback<Option<PackageUrl<'static>>>,
    validator: Callback<String, anyhow::Result<PackageUrl<'static>>>,
    label: String,
    #[prop_or_default]
    r#type: EntryType,
    default: String,
}

#[function_component(SingleEntryVariant)]
fn single_entry(props: &SingleValueEntryProperties) -> Html {
    use patternfly_yew::next::TextArea;
    use patternfly_yew::next::TextInput;

    let state = use_state_eq(|| Err(MSG_NOT_EMPTY.to_string()));

    let input = use_state_eq(|| props.default.clone());

    // feed input with changes
    let oninput = {
        let input = input.clone();
        Callback::from(move |data: String| {
            input.set(data.clone());
        })
    };

    {
        // turn input into state
        let state = state.clone();
        let validator = props.validator.clone();
        use_effect_with_deps(
            move |input| {
                state.set(
                    validator
                        .emit((**input).clone())
                        .map_err(|err| err.to_string()),
                );
            },
            input.clone(),
        );
    }
    {
        // report state to parent component
        let onchange = props.onchange.clone();
        use_effect_with_deps(
            move |state| match &**state {
                Ok(purl) => {
                    onchange.emit(Some((*purl).clone()));
                }
                Err(_) => {
                    onchange.emit(None);
                }
            },
            state.clone(),
        )
    }

    let (alert, helper_text) = match &*state {
        Ok(_) => (None, None),
        Err(err) => (
            Some(FormAlert {
                title: "The form contains fields with errors.".into(),
                r#type: AlertType::Danger,
                children: html!(),
            }),
            Some(FormHelperText::from((err.to_string(), InputState::Error))),
        ),
    };

    html! (
        <Form
            id="lookup-form"
            method="dialog"
            {alert}
        >
            <FormGroup
                label={props.label.clone()}
                required=true
                {helper_text}
            >
                {
                    match &props.r#type {
                        EntryType::Input => html!(
                            <TextInput
                                value={(*input).clone()}
                                {oninput}
                                autofocus=true
                            />
                        ),
                        EntryType::Area => html!(
                            <TextArea
                                value={(*input).clone()}
                                rows={5}
                                resize={ResizeOrientation::Vertical}
                                {oninput}
                                autofocus=true
                            />
                        )
                    }
                }
            </FormGroup>

        </Form>
    )
}

#[function_component(PurlVariant)]
fn purl(props: &PackageLookupProperties) -> Html {
    let validator = Callback::from(|input: String| {
        if input.is_empty() {
            bail!(MSG_NOT_EMPTY);
        }

        Ok(PackageUrl::from_str(&input).context("Unable to parse as Package URL")?)
    });

    html!(
        <SingleEntryVariant
            onchange={props.onchange.clone()}
            {validator}
            label="Package URL (PURL)"
            r#type={EntryType::Input}
            default={DEFAULT_SEARCH}
        />
    )
}

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct LookupPackageModalProperties {
    #[prop_or_default]
    pub onclose: Callback<PackageUrl<'static>>,

    #[prop_or_default]
    pub allow_cancel: bool,

    #[prop_or("Lookup".into())]
    pub label: String,
}

#[function_component(LookupPackageModal)]
pub fn lookup_package_modal(props: &LookupPackageModalProperties) -> Html {
    let backdrop = use_backdrop();

    let purl = use_state_eq(||
        // this is reasonably safe to unwrap, as we control it
        PackageUrl::from_str(DEFAULT_SEARCH).unwrap());
    let form_state = use_state_eq(InputState::default);

    let onclick = {
        let purl = purl.clone();
        let backdrop = backdrop.clone();
        let onclose = props.onclose.clone();
        Callback::from(move |_| {
            if let Some(backdrop) = &backdrop {
                backdrop.close();
            }
            onclose.emit((*purl).clone());
        })
    };

    let oncancel = {
        let backdrop = backdrop.clone();
        Callback::from(move |_| {
            if let Some(backdrop) = &backdrop {
                backdrop.close();
            }
        })
    };

    let footer = {
        html!(
            <>
                <Button
                    variant={ButtonVariant::Primary}
                    disabled={(*form_state) == InputState::Error}
                    r#type={ButtonType::Submit}
                    {onclick}
                    form="lookup-form"
                >
                    { &props.label }
                </Button>
                if props.allow_cancel {
                    <Button
                        variant={ButtonVariant::Secondary}
                        r#type={ButtonType::Button}
                        onclick={oncancel}
                        form="lookup-form"
                    >
                        { "Cancel" }
                    </Button>
                }
            </>
        )
    };

    let onchange = {
        let purl = purl.clone();
        let form_state = form_state.clone();
        Callback::from(move |data: Option<PackageUrl<'static>>| match data {
            Some(data) => {
                purl.set(data);
                form_state.set(InputState::Default)
            }
            None => form_state.set(InputState::Error),
        })
    };

    html!(
        <Bullseye plain=true>
            <Modal
                title="Lookup Package"
                variant={ModalVariant::Medium}
                {footer}
            >
                <PurlVariant {onchange}/>
            </Modal>
        </Bullseye>
    )
}
