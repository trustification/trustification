pub mod csaf;
pub mod cvss;
pub mod highlight;
pub mod search;

use yew::prelude::*;

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
    (page - 1).max(0) * per_page
}

pub struct OrNone<T>(pub Option<T>)
where
    T: Into<Html>;

impl<T> From<OrNone<T>> for Html
where
    T: Into<Html>,
{
    fn from(value: OrNone<T>) -> Self {
        match value.0 {
            Some(value) => value.into(),
            None => html!(<i>{"n/a"}</i>),
        }
    }
}
