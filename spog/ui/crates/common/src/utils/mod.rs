pub mod auth;
pub mod count;
pub mod csaf;
pub mod cvss;
pub mod highlight;
pub mod search;
pub mod time;

use yew::html::{ChildrenRenderer, IntoPropValue};
use yew::prelude::*;
use yew::virtual_dom::VNode;

pub trait RenderOptional: Sized {
    /// Render to HTML, or else …
    fn or_html<F>(self, f: F) -> Html
    where
        F: FnOnce() -> Html;

    /// Render to HTML, or else use "n/a"
    fn or_none(self) -> Html {
        self.or_html(|| html!(<i>{"n/a"}</i>))
    }
}

impl<T> RenderOptional for Option<T>
where
    T: Into<Html>,
{
    fn or_html<F>(self, f: F) -> Html
    where
        F: FnOnce() -> Html,
    {
        match self {
            Some(value) => value.into(),
            None => f(),
        }
    }
}

pub fn pagination_to_offset(page: usize, per_page: usize) -> usize {
    page * per_page
}

pub struct OrNone<T>(pub Option<T>);

impl<T> OrNone<T> {
    pub const DEFAULT_NA: &'static str = "N/A";
}

impl<T> OrNone<T> {
    pub fn map<F, U>(self, f: F) -> OrNone<U>
    where
        F: FnOnce(T) -> U,
    {
        OrNone(self.0.map(f))
    }
}

impl<T> From<OrNone<T>> for Html
where
    T: Into<Html>,
{
    fn from(value: OrNone<T>) -> Self {
        match value.0 {
            Some(value) => value.into(),
            None => html!(<i>{OrNone::<T>::DEFAULT_NA}</i>),
        }
    }
}

impl<T> IntoPropValue<ChildrenRenderer<VNode>> for OrNone<T>
where
    T: Into<Html>,
{
    fn into_prop_value(self) -> ChildrenRenderer<VNode> {
        ChildrenRenderer::new(vec![match self.0 {
            Some(value) => value.into(),
            None => html!(<i>{OrNone::<T>::DEFAULT_NA}</i>),
        }])
    }
}

impl<T> ToHtml for OrNone<T>
where
    T: Into<Html> + Clone,
{
    fn to_html(&self) -> Html {
        match &self.0 {
            Some(value) => value.clone().into(),
            None => html!(<i>{OrNone::<T>::DEFAULT_NA}</i>),
        }
    }

    fn into_html(self) -> Html
    where
        Self: Sized,
    {
        match self.0 {
            Some(value) => value.into(),
            None => html!(<i>{OrNone::<T>::DEFAULT_NA}</i>),
        }
    }
}
