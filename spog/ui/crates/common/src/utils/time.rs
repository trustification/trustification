use chrono::TimeZone;
use time::{macros::format_description, OffsetDateTime};
use yew::prelude::*;

/// Formate a timestamp to represent a date.
pub fn date(dt: OffsetDateTime) -> Html {
    let fmt = format_description!("[month repr:short] [day], [year]");

    let date = dt.date();
    date.format(fmt)
        .unwrap_or_else(|err| {
            log::info!("Failed to format date: {err}");
            date.to_string()
        })
        .into()
}

/// Formate a timestamp to represent a date.
pub fn chrono_date<Tz: TimeZone>(dt: chrono::DateTime<Tz>) -> Html {
    let date = dt.date_naive();
    date.format("%b %d, %Y").into()
}

/// Formate a timestamp to represent a date.
pub fn full_utc_date(date: OffsetDateTime) -> Html {
    let fmt = format_description!("[year]-[month]-[day] [hour]:[minute]:[second] UTC");
    date.format(fmt)
        .unwrap_or_else(|err| {
            log::info!("Failed to format date: {err}");
            date.to_string()
        })
        .into()
}
