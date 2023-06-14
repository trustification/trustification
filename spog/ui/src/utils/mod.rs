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

pub fn last_weeks_date() -> String {
    const DEFAULT_MONTH: &str = "2023-01-01";
    let now = time::OffsetDateTime::now_utc();
    if let Some(last_month) = now.checked_sub(time::Duration::weeks(4)) {
        let f = time::macros::format_description!("[year]-[month]-[day]");
        if let Ok(out) = last_month.format(&f) {
            return out;
        }
    }
    DEFAULT_MONTH.to_string()
}
