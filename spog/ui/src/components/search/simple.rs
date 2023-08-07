use crate::utils::search::*;
use patternfly_yew::prelude::*;
use std::borrow::Cow;
use std::collections::HashSet;
use std::rc::Rc;
use yew::prelude::*;

#[derive(Clone)]
pub struct Search<T> {
    pub categories: Vec<SearchCategory<T>>,
}

impl<T> Search<T> {
    pub fn category_labels(&self) -> impl Iterator<Item = &str> {
        self.categories.iter().map(|cat| cat.title.as_str())
    }
}

#[derive(Clone)]
pub struct SearchCategory<T> {
    pub title: String,
    pub options: Vec<SearchOption<T>>,
}

#[derive(Clone)]
pub enum LabelProvider {
    Static(Html),
    Dynamic(Rc<dyn Fn() -> Html>),
}

impl From<String> for LabelProvider {
    fn from(value: String) -> Self {
        Self::Static(Html::from(value))
    }
}

impl From<&str> for LabelProvider {
    fn from(value: &str) -> Self {
        Self::Static(Html::from(value))
    }
}

impl From<Html> for LabelProvider {
    fn from(value: Html) -> Self {
        Self::Static(value)
    }
}

impl From<&LabelProvider> for Html {
    fn from(value: &LabelProvider) -> Self {
        match value {
            LabelProvider::Static(html) => html.clone(),
            LabelProvider::Dynamic(f) => f(),
        }
    }
}

pub type SearchOptionGetter<T> = Rc<dyn Fn(&T) -> bool>;
pub type SearchOptionSetter<T> = Rc<dyn Fn(&mut T, bool)>;

#[derive(Clone)]
pub enum SearchOption<T> {
    Check(SearchOptionCheck<T>),
    Divider,
}

#[derive(Clone)]
pub struct SearchOptionCheck<T> {
    pub label: LabelProvider,
    pub getter: SearchOptionGetter<T>,
    pub setter: SearchOptionSetter<T>,
}

impl<T> SearchOption<T> {
    #[allow(unused)]
    pub fn new_check<L, G, S>(label: L, getter: G, setter: S) -> Self
    where
        L: Into<LabelProvider>,
        G: Fn(&T) -> bool + 'static,
        S: Fn(&mut T, bool) + 'static,
    {
        Self::Check(SearchOptionCheck {
            label: label.into(),
            getter: Rc::new(getter),
            setter: Rc::new(setter),
        })
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
    T: ToFilterExpression + SimpleProperties + Default + Clone,
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

    pub fn as_str(&self, context: &T::Context) -> Cow<'_, str> {
        match self {
            Self::Complex(s) => s.into(),
            Self::Simple(s) => s.to_filter_expression(context).into(),
        }
    }

    pub fn set_simple_terms(&self, new_terms: Vec<String>) -> Self {
        let mut new = match self {
            Self::Complex(_) => T::default(),
            Self::Simple(terms) => terms.clone(),
        };

        *new.terms_mut() = new_terms;
        Self::Simple(new)
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

#[derive(Properties)]
pub struct SimpleSearchProperties<T>
where
    T: PartialEq + Clone + ToFilterExpression + 'static,
{
    pub search: Rc<Search<T>>,
    pub search_params: UseStateHandle<SearchMode<T>>,
}

impl<T> PartialEq for SimpleSearchProperties<T>
where
    T: PartialEq + Clone + ToFilterExpression + 'static,
{
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.search, &other.search) && self.search_params.eq(&other.search_params)
    }
}

#[function_component(SimpleSearch)]
pub fn simple_search<T>(props: &SimpleSearchProperties<T>) -> Html
where
    T: Default + PartialEq + Clone + ToFilterExpression + SimpleProperties + 'static,
{
    let filter_expansion = {
        let search = props.search.clone();
        use_state(|| {
            search
                .category_labels()
                .map(|s| Rc::new(s.to_string()))
                .collect::<HashSet<Rc<String>>>()
        })
    };

    let filter_section = |title: Rc<String>, children: Html| {
        let expanded = filter_expansion.contains(&title);

        let onclick = {
            let title = title.clone();
            let filter_expansion = filter_expansion.clone();
            Callback::from(move |()| {
                let mut selection = (*filter_expansion).clone();
                if selection.contains(&title) {
                    selection.remove(&title);
                } else {
                    selection.insert(title.clone());
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

    let onclear = use_callback(
        |_, search_params| {
            if let SearchMode::Simple(_) = &**search_params {
                search_params.set(SearchMode::Simple(T::default()));
            }
        },
        props.search_params.clone(),
    );
    let canclear = props.search_params.is_simple();

    html!(
        <>
            <Button label="Clear all filters" onclick={onclear} variant={ButtonVariant::Link} disabled={!canclear} />
            <Accordion large=true>
                {
                    for props.search.categories.iter().map(|cat| {
                        filter_section(
                            Rc::new(cat.title.clone()),
                            html!(
                                <List r#type={ListType::Plain}>
                                    { for cat.options.iter().map(|opt|render_opt(props, opt))}
                                </List>
                            ),
                        )
                    })
                }
            </Accordion>
        </>
    )
}

fn render_opt<T>(props: &SimpleSearchProperties<T>, opt: &SearchOption<T>) -> Html
where
    T: Default + PartialEq + Clone + ToFilterExpression + SimpleProperties + 'static,
{
    match opt {
        SearchOption::Divider => {
            html!(<ListDivider/>)
        }
        SearchOption::Check(opt) => {
            let active = props.search_params.is_simple();

            let opt = opt.clone();
            html!(
                <Check
                    checked={(*props.search_params).map_bool(|s|(opt.getter)(s))}
                    onchange={search_set(props.search_params.clone(), move |s, state|(opt.setter)(s, state))}
                    disabled={!active}
                >
                    { &opt.label }
                </Check>
            )
        }
    }
}

#[derive(PartialEq, Properties)]
pub struct SimpleModeSwitchProperties {
    pub simple: bool,
    pub ontoggle: Callback<bool>,
}

#[function_component(SimpleModeSwitch)]
pub fn simple_mode_switch(props: &SimpleModeSwitchProperties) -> Html {
    html!(
        <Flex>
            <FlexItem modifiers={[FlexModifier::Column, FlexModifier::Align(Alignment::Center)]}>
                <Title level={Level::H2}>
                    { "Categories " }
                </Title>
            </FlexItem>
            <FlexItem modifiers={[FlexModifier::Column, FlexModifier::Align(Alignment::Center)]}>
                <Switch checked={props.simple} label="Simple" label_off="Complex" onchange={props.ontoggle.clone()}/>
            </FlexItem>
        </Flex>
    )
}
