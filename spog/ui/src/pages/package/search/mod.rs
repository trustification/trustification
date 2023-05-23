mod lookup;

use crate::backend::PackageService;
use crate::components::deps::PackageReferences;
use crate::hooks::use_backend;
use packageurl::PackageUrl;
use patternfly_yew::{
    next::{Toolbar, ToolbarContent},
    prelude::*,
};
use std::str::FromStr;
use strum::IntoEnumIterator;
use yew::prelude::*;
use yew_more_hooks::hooks::{use_async_with_cloned_deps, UseAsyncState};

fn default_purl() -> PackageUrl<'static> {
    PackageUrl::from_str("pkg:maven/io.quarkus/quarkus-core").unwrap()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, strum::Display, strum::EnumIter)]
pub enum Criteria {
    Type,
    Namespace,
    Name,
    Version,
}

impl Criteria {
    fn onremove(&self, state: UseStateHandle<PackageUrl<'static>>) -> Option<Callback<()>> {
        match self {
            Self::Namespace => Some(Callback::from(move |_| {
                let mut purl = (*state).clone();
                purl.without_namespace();
                state.set(purl);
            })),
            Self::Version => Some(Callback::from(move |_| {
                let mut purl = (*state).clone();
                purl.without_version();
                state.set(purl);
            })),
            _ => None,
        }
    }

    /// get the text for the edit component
    fn get(&self, state: &UseStateHandle<PackageUrl<'static>>) -> String {
        let purl = &**state;
        match self {
            Self::Type => purl.ty().to_string(),
            Self::Namespace => purl
                .namespace()
                .map(ToString::to_string)
                .unwrap_or_default(),
            Self::Name => purl.name().to_string(),
            Self::Version => purl.version().map(ToString::to_string).unwrap_or_default(),
        }
    }

    fn set(&self, state: &mut UseStateHandle<PackageUrl<'static>>, text: &UseStateHandle<String>) {
        let mut purl = (**state).clone();

        fn copy_optional(source: &PackageUrl, target: &mut PackageUrl) {
            if let Some(namespace) = source.namespace() {
                target.with_namespace(namespace.to_string());
            }
            if let Some(version) = source.version() {
                target.with_version(version.to_string());
            }
        }

        match self {
            Self::Type => {
                let name = purl.name().to_string();
                purl = match PackageUrl::new((**text).clone(), name) {
                    Ok(mut new_purl) => {
                        copy_optional(&purl, &mut new_purl);
                        new_purl
                    }
                    Err(_err) => (**state).clone(),
                };
            }
            Self::Namespace => {
                purl.with_namespace((**text).clone());
            }
            Self::Name => {
                let r#type = purl.ty().to_string();
                purl = match PackageUrl::new(r#type, (**text).clone()) {
                    Ok(mut new_purl) => {
                        copy_optional(&purl, &mut new_purl);
                        new_purl
                    }
                    Err(_err) => (**state).clone(),
                };
            }
            Self::Version => {
                purl.with_version((**text).clone());
            }
        };

        state.set(purl);
    }
}

#[function_component(PackageSearch)]
pub fn package_search() -> Html {
    let backend = use_backend();

    let service = use_memo(
        |backend| PackageService::new((**backend).clone()),
        backend.clone(),
    );

    let state = use_state_eq(|| {
        // initialize with the state from history, or with a reasonable default
        gloo_utils::history()
            .state()
            .ok()
            .and_then(|state| state.as_string())
            .and_then(|state| PackageUrl::from_str(&state).ok())
            .unwrap_or_else(default_purl)
    });

    let purl = (*state).clone();

    let mut filters = vec![];

    let mut add_filter = |name: &str, text: String, onremove: Option<Callback<()>>| {
        filters.push(html_nested!(
            <ToolbarItem>
                <ChipGroup label={name.to_string()}>
                    <Chip {text} onclose={onremove}/>
                </ChipGroup>
            </ToolbarItem>
        ));
    };

    add_filter("Type", purl.ty().to_string(), None);
    if let Some(namespace) = purl.namespace() {
        add_filter(
            "Namespace",
            namespace.to_string(),
            Criteria::Namespace.onremove(state.clone()),
        );
    }
    add_filter("Name", purl.name().to_string(), None);
    if let Some(version) = purl.version() {
        add_filter(
            "Version",
            version.to_string(),
            Criteria::Version.onremove(state.clone()),
        );
    }

    let onreset = {
        let state = state.clone();
        Callback::from(move |_| {
            state.set(default_purl());
        })
    };

    filters.push(html_nested!(
        <ToolbarItem>
            <Button variant={ButtonVariant::Link} label="Reset" onclick={onreset}/>
        </ToolbarItem>
    ));

    let text = use_state_eq(String::new);
    let criteria = use_state_eq(|| None);

    let onvariant = {
        let state = state.clone();
        let text = text.clone();
        let criteria = criteria.clone();
        Callback::from(move |data: Criteria| {
            criteria.set(Some(data));
            text.set(data.get(&state));
        })
    };

    let onclear = criteria.and_then(|c| {
        c.onremove(state.clone())
            .map(|cb| cb.reform(|_: MouseEvent| ()))
    });
    let onset = {
        let criteria = criteria.clone();
        let state = state.clone();
        let text = text.clone();
        Callback::from(move |_| {
            if let Some(criteria) = *criteria {
                criteria.set(&mut state.clone(), &text);
            }
        })
    };

    let set_disabled = criteria.is_none();

    let search = {
        let service = service.clone();
        use_async_with_cloned_deps(
            move |purl| async move { service.search(vec![purl]).await },
            (*state).clone(),
        )
    };

    use_effect_with_deps(
        |purl| {
            // store changes to the state in the current history
            let purl = purl.to_string();
            let _ = gloo_utils::history().replace_state(&purl.into(), "");
        },
        (*state).clone(),
    );

    let backdrop = use_backdrop();
    let onfrompurl = {
        let state = state.clone();
        let onclose = Callback::from(move |purl| {
            state.set(purl);
        });
        Callback::from(move |_| {
            if let Some(backdrop) = &backdrop {
                backdrop.open(html!( <lookup::LookupPackageModal
                        allow_cancel=true
                        label="Ok"
                        onclose={onclose.clone()}
                    /> ));
            }
        })
    };

    html!(
        <>
            <Toolbar>
                <ToolbarContent>
                    <ToolbarGroup>
                        <ToolbarItem r#type={ToolbarItemType::SearchFilter} width={["600px".to_string()]}>
                            <InputGroup>
                                <div style="width: 300px;">
                                    <Select<Criteria> icon={Icon::Filter} placeholder="Criteria" variant={SelectVariant::Single(onvariant)}>
                                        {for Criteria::iter().map(|value| html_nested! (
                                            <SelectOption<Criteria> {value}/>
                                        )) }
                                    </Select<Criteria>>
                                </div>
                                <TextInputGroup>
                                    <TextInputGroupMain
                                        icon={Icon::Search}
                                        placeholder="Filter"
                                        value={(*text).clone()}
                                        oninput={ Callback::from(move |data| text.set(data)) }
                                    />
                                    if let Some(onclear) = onclear {
                                        <TextInputGroupUtilities>
                                            <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclear} />
                                        </TextInputGroupUtilities>
                                    }
                                    <Button icon={Icon::ArrowRight} variant={ButtonVariant::Control} onclick={onset} disabled={set_disabled} />
                                </TextInputGroup>
                            </InputGroup>
                        </ToolbarItem>
                        <ToolbarItem>
                            <Button label="From Package URL" variant={ButtonVariant::Secondary} onclick={onfrompurl} />
                        </ToolbarItem>
                    </ToolbarGroup>
                </ToolbarContent>
                <ToolbarContent> { for filters.into_iter() } </ToolbarContent>
            </Toolbar>

            {
                match &*search {
                    UseAsyncState::Pending | UseAsyncState::Processing => { html!(<Spinner/>) }
                    UseAsyncState::Ready(Ok(result)) if result.is_empty() => {
                        html!(
                            <Bullseye>
                                <EmptyState
                                    title="No results"
                                    icon={Icon::Search}
                                >
                                    { "Try some different query parameters." }
                                </EmptyState>
                            </Bullseye>
                        )
                    },
                    UseAsyncState::Ready(Ok(result)) => {
                        let refs = result.0.clone();
                        html!(<PackageReferences {refs} />)
                    },
                    UseAsyncState::Ready(Err(err)) => html!(
                        <Bullseye>
                            <Title>{"Search error"}</Title>
                            { err }
                        </Bullseye>
                    ),
                }
            }

        </>
    )
}
