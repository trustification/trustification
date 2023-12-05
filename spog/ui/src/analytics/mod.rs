use analytics_next::TrackingEvent;
use serde_json::json;

pub struct AnalyticEvents {
    pub page: ObjectNameAnalytics,
    pub action: ActionAnalytics,
}

pub enum ObjectNameAnalytics {
    HomePage,
    UniversalSearchPage,
}

pub enum ActionAnalytics {
    Search(String),
    SelectTab(String),
}

impl std::fmt::Display for ObjectNameAnalytics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HomePage => f.write_str("HomePage"),
            Self::UniversalSearchPage => f.write_str("UniversalSearchPage"),
        }
    }
}

impl std::fmt::Display for ActionAnalytics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Search(_) => f.write_str("Search"),
            Self::SelectTab(_) => f.write_str("SelectTab"),
        }
    }
}

impl From<AnalyticEvents> for TrackingEvent<'static> {
    fn from(value: AnalyticEvents) -> Self {
        let event_key = format!("{} {}", value.page, value.action);
        let json = match value.action {
            ActionAnalytics::Search(filter_text) => json!({ "filter_text": filter_text }),
            ActionAnalytics::SelectTab(tab_name) => json!({ "tab_name": tab_name }),
        };
        (event_key, json).into()
    }
}
