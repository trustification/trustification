use chrono::{DateTime, Utc};
use time::OffsetDateTime;
use yew::html::IntoPropValue;
use yew::prelude::*;

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum TimestampValue {
    Time(OffsetDateTime),
    Chrono(DateTime<Utc>),
}

impl From<OffsetDateTime> for TimestampValue {
    fn from(value: OffsetDateTime) -> Self {
        Self::Time(value)
    }
}

impl From<DateTime<Utc>> for TimestampValue {
    fn from(value: DateTime<Utc>) -> Self {
        Self::Chrono(value)
    }
}

impl IntoPropValue<TimestampValue> for DateTime<Utc> {
    fn into_prop_value(self) -> TimestampValue {
        TimestampValue::Chrono(self)
    }
}

impl IntoPropValue<TimestampValue> for OffsetDateTime {
    fn into_prop_value(self) -> TimestampValue {
        TimestampValue::Time(self)
    }
}

#[derive(PartialEq, Properties)]
pub struct TimestampProperties {
    pub timestamp: TimestampValue,
}

/// Render the date portion of a timestamp.
#[function_component(Date)]
pub fn date(props: &TimestampProperties) -> Html {
    html!(
        <span>{
            match props.timestamp {
                TimestampValue::Chrono(value) => spog_ui_common::utils::time::chrono_date(value),
                TimestampValue::Time(value) => spog_ui_common::utils::time::date(value),
            }
        }</span>
    )
}
