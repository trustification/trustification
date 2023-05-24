pub mod cvss;

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
