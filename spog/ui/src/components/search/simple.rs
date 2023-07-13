use crate::utils::search::*;
use patternfly_yew::prelude::*;
use std::borrow::Cow;
use std::collections::HashSet;
use std::sync::Arc;
use yew::prelude::*;

pub struct Search<T> {
    pub categories: Vec<SearchCategory<T>>,
}

impl<T> Search<T> {
    pub fn category_labels<C>(&self) -> C
    where
        C: FromIterator<&'static str>,
    {
        self.categories.iter().map(|cat| cat.title).collect()
    }
}

pub struct SearchCategory<T> {
    pub title: &'static str,
    pub options: Vec<SearchOption<T>>,
}

pub struct SearchOption<T> {
    pub label: Arc<dyn Fn() -> Html + Send + Sync>,
    pub getter: Arc<dyn Fn(&T) -> bool + Send + Sync>,
    pub setter: Arc<dyn Fn(&mut T, bool) + Send + Sync>,
}

impl<T> SearchOption<T> {
    pub fn new_str<L, G, S>(label: L, getter: G, setter: S) -> Self
    where
        L: Into<Html> + Clone + Send + Sync + 'static,
        G: Fn(&T) -> bool + Send + Sync + 'static,
        S: Fn(&mut T, bool) + Send + Sync + 'static,
    {
        Self {
            label: Arc::new(move || label.clone().into()),
            getter: Arc::new(getter),
            setter: Arc::new(setter),
        }
    }

    pub fn new_fn<L, G, S>(label: L, getter: G, setter: S) -> Self
    where
        L: Fn() -> Html + Send + Sync + 'static,
        G: Fn(&T) -> bool + Send + Sync + 'static,
        S: Fn(&mut T, bool) + Send + Sync + 'static,
    {
        Self {
            label: Arc::new(label),
            getter: Arc::new(getter),
            setter: Arc::new(setter),
        }
    }
}

fn search_set<T, F>(search: UseStateHandle<SearchMode<T>>, f: F) -> Callback<bool>
where
    T: Clone + 'static,
    F: Fn(&mut T, bool) + 'static,
{
    Callback::from(move |state| {
        if let SearchMode::Simple(simple) = &*search {
            let mut simple = simple.clone();
            f(&mut simple, state);
            search.set(SearchMode::Simple(simple));
        }
    })
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum SearchMode<T> {
    Complex(String),
    Simple(T),
}

impl<T> SearchMode<T>
where
    T: ToFilterExpression,
{
    pub fn is_simple(&self) -> bool {
        matches!(self, Self::Simple(_))
    }

    pub fn map_bool<F>(&self, f: F) -> bool
    where
        F: FnOnce(&T) -> bool,
    {
        match self {
            Self::Simple(s) => f(s),
            Self::Complex(_) => false,
        }
    }

    pub fn as_str(&self) -> Cow<'_, str> {
        match self {
            Self::Complex(s) => s.into(),
            Self::Simple(s) => s.to_filter_expression().into(),
        }
    }
}

impl<T> Default for SearchMode<T>
where
    T: Default,
{
    fn default() -> Self {
        Self::Simple(Default::default())
    }
}

pub fn simple_search<T>(
    search: &'static Search<T>,
    search_params: UseStateHandle<SearchMode<T>>,
    filter_expansion: UseStateHandle<HashSet<&'static str>>,
) -> Html
where
    T: Clone + ToFilterExpression,
{
    let active = search_params.is_simple();

    let filter_section = |title: &'static str, children: Html| {
        let expanded = filter_expansion.contains(title);

        let onclick = {
            let filter_expansion = filter_expansion.clone();
            Callback::from(move |()| {
                let mut selection = (*filter_expansion).clone();
                if selection.contains(title) {
                    selection.remove(title);
                } else {
                    selection.insert(title);
                }
                filter_expansion.set(selection);
            })
        };

        html_nested!(
            <AccordionItem title={title.to_string()} {expanded} {onclick}>
                { children }
            </AccordionItem>
        )
    };

    html!(
        <Accordion large=true bordered=true> {
            for search
                .categories
                .iter()
                .map(|cat| {
                    filter_section(
                        cat.title,
                        html!(
                            <List r#type={ListType::Plain}>
                                { for cat.options.iter().map(|opt|{
                                    html!(
                                        <Check
                                            checked={(*search_params).map_bool(|s|(opt.getter)(s))}
                                            onchange={search_set(search_params.clone(), |s, state|(opt.setter)(s, state))}
                                            disabled={!active}
                                        >
                                            { (opt.label)() }
                                        </Check>
                                    )
                                })}
                            </List>
                        ),
                    )
                })
        } </Accordion>
    )
}

#[derive(PartialEq, Properties)]
pub struct SimpleModeSwitchProperties {
    pub simple: bool,
    pub ontoggle: Callback<bool>,
}

#[function_component(SimpleModeSwitch)]
pub fn simple_mode_switch(props: &SimpleModeSwitchProperties) -> Html {
    html!(
        <div style="height: 100%; display: flex; flex-direction: row; align-items: center;">
            <Title level={Level::H2}>{ "Categories " } <Switch checked={props.simple} label="Simple" label_off="Complex" onchange={props.ontoggle.clone()}/> </Title>
        </div>
    )
}
