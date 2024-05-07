use crate::analytics::SearchContext;
use crate::search::DynamicSearchParameters;
use analytics_next::tracking;
use patternfly_yew::prelude::*;
use spog_ui_common::utils::search::*;
use spog_ui_utils::analytics::use_analytics;
use std::collections::HashSet;
use std::ops::{Deref, DerefMut};
use std::rc::Rc;
use yew::html::{ChildrenRenderer, IntoPropValue};
use yew::prelude::*;
use yew::virtual_dom::VNode;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchDefaults(pub Vec<DefaultEntry>);

impl SearchDefaults {
    pub fn apply_defaults<T>(self, mode: &mut SearchMode<T>)
    where
        T: ToFilterExpression + SimpleProperties<Defaults = SearchDefaults> + Default + Clone,
    {
        if let SearchMode::Simple(mode) = mode {
            mode.apply_defaults(self);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefaultEntry {
    pub category: Rc<String>,
    pub id: Rc<String>,
    pub value: Rc<String>,
}

#[derive(Clone)]
pub struct Search {
    pub categories: Vec<SearchCategory>,
    pub context: SearchContext,
}

impl Search {
    pub fn category_labels(&self) -> impl Iterator<Item = &str> {
        self.categories.iter().map(|cat| cat.title.as_str())
    }
}

#[derive(Clone)]
pub struct SearchCategory {
    pub title: String,
    pub options: Vec<SearchOption>,
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

impl IntoPropValue<OptionalHtml> for LabelProvider {
    fn into_prop_value(self) -> OptionalHtml {
        match self {
            LabelProvider::Static(html) => html,
            LabelProvider::Dynamic(f) => f(),
        }
        .into()
    }
}

impl IntoPropValue<ChildrenRenderer<VNode>> for LabelProvider {
    fn into_prop_value(self) -> ChildrenRenderer<VNode> {
        ChildrenRenderer::new(vec![match self {
            LabelProvider::Static(html) => html,
            LabelProvider::Dynamic(f) => f(),
        }])
    }
}

pub type SearchOptionGetter<T> = Rc<dyn Fn(&T) -> bool>;
pub type SearchOptionSetter<T> = Rc<dyn Fn(&mut T, bool)>;

#[derive(Clone)]
pub enum SearchOption {
    Check(SearchOptionCheck),
    Select(SearchOptionSelect),
    Divider,
}

#[derive(Clone)]
pub struct SearchOptionCheck {
    pub label: LabelProvider,
    pub getter: SearchOptionGetter<DynamicSearchParameters>,
    pub setter: SearchOptionSetter<DynamicSearchParameters>,
}

#[derive(Clone)]
pub struct SearchOptionSelectItem {
    pub label: LabelProvider,
    pub getter: SearchOptionGetter<DynamicSearchParameters>,
    pub setter: SearchOptionSetter<DynamicSearchParameters>,
}

#[derive(Clone)]
pub struct SearchOptionSelect {
    pub options: Vec<SearchOptionSelectItem>,
}

impl SearchOption {
    #[allow(unused)]
    pub fn new_check<L, G, S>(label: L, getter: G, setter: S) -> Self
    where
        L: Into<LabelProvider>,
        G: Fn(&DynamicSearchParameters) -> bool + 'static,
        S: Fn(&mut DynamicSearchParameters, bool) + 'static,
    {
        Self::Check(SearchOptionCheck {
            label: label.into(),
            getter: Rc::new(getter),
            setter: Rc::new(setter),
        })
    }
}

fn search_set<F>(search: UseReducerHandle<SearchState<DynamicSearchParameters>>, f: F) -> Callback<bool>
where
    F: Fn(&mut DynamicSearchParameters, bool) + 'static,
{
    Callback::from(move |state| {
        if let SearchMode::Simple(simple) = &**search {
            let mut simple = simple.clone();
            f(&mut simple, state);
            search.dispatch(SearchModeAction::SetSimple(simple));
        }
    })
}

pub enum SearchModeAction {
    /// Set new search terms for either complex or simple mode
    SetTerms(String),
    /// When in simple mode, set new search terms
    SetSimpleTerms(Vec<String>),
    /// Apply the defaults, if no user interaction has taken place yet
    ApplyDefault(SearchDefaults),
    /// Clear the search, keeping the same search mode
    Clear,
    /// Set complex mode, with provided query
    SetComplex(String),
    /// Set simple mode, with provided state
    SetSimple(DynamicSearchParameters),
    /// When in simple mode, set sort order
    SetSimpleSort((String, Order)),
}

impl Reducible for SearchState<DynamicSearchParameters> {
    type Action = SearchModeAction;

    fn reduce(self: Rc<Self>, action: Self::Action) -> Rc<Self> {
        match action {
            Self::Action::SetTerms(terms) => Rc::new(self.update(|mode| match mode {
                SearchMode::Complex(_) => SearchMode::Complex(terms),
                SearchMode::Simple(s) => {
                    let mut s = s.clone();
                    *s.terms_mut() = terms.split(' ').map(|s| s.to_string()).collect();
                    SearchMode::Simple(s)
                }
            })),
            Self::Action::ApplyDefault(defaults) => {
                let mut new = (*self).clone();
                new.defaults = Some(defaults.clone());
                if !new.modified {
                    defaults.apply_defaults(&mut new);
                }
                Rc::new(new)
            }
            Self::Action::Clear => {
                let mut new = self.update(|mode| mode.reset()).unmodified();
                if let Some(defaults) = self.defaults.clone() {
                    defaults.apply_defaults(&mut new.mode);
                }
                Rc::new(new)
            }
            Self::Action::SetComplex(terms) => Rc::new(self.replace(SearchMode::Complex(terms))),
            Self::Action::SetSimple(t) => Rc::new(self.replace(SearchMode::Simple(t))),
            Self::Action::SetSimpleSort(sort_by) => Rc::new(self.update(|mode| match mode {
                SearchMode::Complex(_) => mode.clone(),
                SearchMode::Simple(s) => {
                    let mut s = (*s).clone();
                    s.set_sort_by(sort_by);
                    SearchMode::Simple(s)
                }
            })),
            Self::Action::SetSimpleTerms(terms) => Rc::new(self.update(|mode| match mode {
                SearchMode::Complex(_) => mode.clone(),
                SearchMode::Simple(s) => {
                    let mut s = (*s).clone();
                    (*s.terms_mut()) = terms;
                    SearchMode::Simple(s)
                }
            })),
        }
    }
}

/// The persisted search state
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Deserialize, serde::Serialize)]
pub struct HistorySearchState<T> {
    /// the current search mode and its options
    pub mode: SearchMode<T>,
    /// a flag indicating if the user modified the search options
    pub modified: bool,
}

impl<T> From<HistorySearchState<T>> for SearchState<T> {
    fn from(value: HistorySearchState<T>) -> Self {
        Self {
            mode: value.mode,
            modified: value.modified,
            defaults: None,
        }
    }
}

impl<T> From<SearchState<T>> for HistorySearchState<T> {
    fn from(value: SearchState<T>) -> Self {
        Self {
            mode: value.mode,
            modified: value.modified,
        }
    }
}

impl<T> From<SearchMode<T>> for HistorySearchState<T> {
    fn from(mode: SearchMode<T>) -> Self {
        Self { modified: false, mode }
    }
}

/// Tracking the full search state
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SearchState<T> {
    /// the current search mode and its options
    pub mode: SearchMode<T>,
    /// the registered defaults
    pub defaults: Option<SearchDefaults>,
    /// a flag indicating if the user modified the search options
    pub modified: bool,
}

impl<T> SearchState<T> {
    /// Mutate the current search state and mark as modified
    pub fn update<F>(&self, f: F) -> Self
    where
        F: FnOnce(&SearchMode<T>) -> SearchMode<T>,
    {
        Self {
            mode: f(&self.mode),
            defaults: self.defaults.clone(),
            modified: true,
        }
    }

    /// Replace the current search mode and mark as modified
    pub fn replace(&self, mode: SearchMode<T>) -> Self {
        Self {
            mode,
            defaults: self.defaults.clone(),
            modified: true,
        }
    }

    /// mark the state as "unmodifed"
    pub fn unmodified(mut self) -> Self {
        self.modified = false;
        self
    }
}

impl<T> Deref for SearchState<T> {
    type Target = SearchMode<T>;

    fn deref(&self) -> &Self::Target {
        &self.mode
    }
}

impl<T> DerefMut for SearchState<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.mode
    }
}

impl<T> From<SearchMode<T>> for SearchState<T> {
    fn from(mode: SearchMode<T>) -> Self {
        Self {
            mode,
            defaults: None,
            modified: false,
        }
    }
}

/// The mode the search is in.
///
/// * Complex: the user specifies a full search string
/// * Simple: the user may choose from some options, and enter some search terms
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

    pub fn as_str(&self, context: &T::Context) -> String {
        match self {
            Self::Complex(s) => s.into(),
            Self::Simple(s) => s.to_filter_expression(context),
        }
    }

    /// Set mode to simple and apply new search terms
    ///
    /// **NOTE:** If the search is in complex mode, this will reset it to simple mode.
    pub fn set_simple_terms(&self, new_terms: Vec<String>) -> Self {
        let mut new = match self {
            Self::Complex(_) => T::default(),
            Self::Simple(terms) => terms.clone(),
        };

        *new.terms_mut() = new_terms;
        Self::Simple(new)
    }

    /// Reset filters, but keep mode
    pub fn reset(&self) -> Self {
        match self {
            Self::Complex(_) => Self::Complex(Default::default()),
            Self::Simple(_) => Self::Simple(Default::default()),
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

#[derive(Properties)]
pub struct SimpleSearchProperties {
    pub search: Rc<Search>,
    pub search_params: UseReducerHandle<SearchState<DynamicSearchParameters>>,
}

impl PartialEq for SimpleSearchProperties {
    fn eq(&self, other: &Self) -> bool {
        Rc::ptr_eq(&self.search, &other.search) && self.search_params.eq(&other.search_params)
    }
}

#[function_component(SimpleSearch)]
pub fn simple_search(props: &SimpleSearchProperties) -> Html {
    let analytics = use_analytics();
    let search = props.search.context;

    #[derive(serde::Serialize)]
    #[tracking("Expand Section")]
    struct ExpandSection<'a> {
        title: &'a str,
        expanded: bool,
        search: SearchContext,
    }

    #[derive(serde::Serialize)]
    #[tracking("Reset filter")]
    struct ResetFilter {
        search: SearchContext,
    }

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
            let analytics = analytics.clone();
            Callback::from(move |()| {
                let mut selection = (*filter_expansion).clone();
                if selection.contains(&title) {
                    selection.remove(&title);
                    analytics.track(ExpandSection {
                        title: &title,
                        expanded: false,
                        search,
                    });
                } else {
                    selection.insert(title.clone());
                    analytics.track(ExpandSection {
                        title: &title,
                        expanded: true,
                        search,
                    });
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
        (props.search_params.clone(), analytics.clone(), search),
        |_, (search_params, analytics, search)| {
            if let SearchMode::Simple(_) = &***search_params {
                search_params.dispatch(SearchModeAction::Clear);
            }
            analytics.track(ResetFilter { search: *search });
        },
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
                                    { for cat.options.iter().map(|opt| html_nested!(
                                        <ListItem>{render_opt(props, opt)}</ListItem>
                                    ))}
                                </List>
                            ),
                        )
                    })
                }
            </Accordion>
        </>
    )
}

fn render_opt(props: &SimpleSearchProperties, opt: &SearchOption) -> Html {
    match opt {
        SearchOption::Divider => {
            html!(<ListDivider/>)
        }
        SearchOption::Check(opt) => {
            let active = props.search_params.is_simple();
            let opt = opt.clone();

            html!(
                <Checkbox
                    checked={(*props.search_params).map_bool(|s|(opt.getter)(s))}
                    onchange={search_set(props.search_params.clone(), move |s, state|(opt.setter)(s, state)).reform(|state: CheckboxState| state.into())}
                    disabled={!active}
                    label={opt.label.clone()}
                />
            )
        }
        SearchOption::Select(select) => {
            let active = props.search_params.is_simple();
            let select = select.clone();

            select
                .options
                .iter()
                .map(|opt| {
                    let opt = opt.clone();
                    html!(
                        <Radio
                            checked={(*props.search_params).map_bool(|s|(opt.getter)(s))}
                            onchange={search_set(props.search_params.clone(), move |s, _state|(opt.setter)(s, true)).reform(|_|true)}
                            disabled={!active}
                        >
                            { opt.label.clone() }
                        </Radio>
                    )
                })
                .collect::<Html>()
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
