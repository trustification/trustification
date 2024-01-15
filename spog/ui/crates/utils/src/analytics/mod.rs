mod component;
mod r#macro;

pub use component::*;

use analytics_next::{AnalyticsBrowser, Settings, TrackingEvent, User};
use openidconnect::LocalizedClaim;
use serde::Serialize;
use serde_json::{json, Value};
use spog_ui_backend::use_backend;
use spog_ui_common::utils::auth::claims;
use std::ops::Deref;
use yew::prelude::*;
use yew_consent::prelude::*;
use yew_nested_router::history::History;
use yew_oauth2::prelude::use_auth_state;

#[derive(Clone, PartialEq)]
pub struct UseAnalytics {
    context: AnalyticsContext,
}

impl Deref for UseAnalytics {
    type Target = AnalyticsContext;

    fn deref(&self) -> &Self::Target {
        &self.context
    }
}

#[derive(Clone, Default, PartialEq)]
pub struct AnalyticsContext {
    analytics: Option<AnalyticsBrowser>,
}

impl AnalyticsContext {
    /// check if analytics is active
    pub fn is_active(&self) -> bool {
        self.analytics.is_some()
    }

    /// trigger an "identify" event, if enabled
    pub fn identify(&self, user: impl Into<User>) {
        if let Some(analytics) = &self.analytics {
            analytics.identify(user);
        }
    }

    /// trigger a "tracking" event, if enabled
    pub fn track<'a>(&self, event: impl Into<TrackingEvent<'a>>) {
        #[cfg(debug_assertions)]
        {
            let event = event.into();
            log::debug!("Tracking event: {event:?}");
            if let Some(analytics) = &self.analytics {
                analytics.track(event);
            }
        }
        #[cfg(not(debug_assertions))]
        if let Some(analytics) = &self.analytics {
            analytics.track(event);
        }
    }

    /// trigger a "page" event, if enabled
    pub fn page(&self) {
        if let Some(analytics) = &self.analytics {
            analytics.page();
        }
    }
}

/// Fetch the analytics context.
///
/// Possibly a "no-op" context if the user didn't consent to tracking or the call is done outside
/// a component wrapped by [`Segment`].
#[hook]
pub fn use_analytics() -> UseAnalytics {
    UseAnalytics {
        context: use_context::<AnalyticsContext>().unwrap_or_default(),
    }
}

#[derive(PartialEq, Properties)]
pub struct SegmentProperties {
    /// The segment.io "write key"
    #[prop_or_default]
    pub write_key: Option<String>,

    #[prop_or_default]
    pub children: Children,
}

/// Inject the segment tracking context, if permitted
#[function_component(Segment)]
pub fn segment(props: &SegmentProperties) -> Html {
    let consent = use_consent();
    let backend = use_backend();

    match (consent, backend.endpoints.external_consent) {
        // if we have consent, or consent is managed externally
        (_, true) | (ConsentState::Yes(()), _) => {
            let analytics = build(props.write_key.as_deref());
            let context = AnalyticsContext { analytics };

            html!(
                <ContextProvider<AnalyticsContext> {context}>
                    <SegmentPageTracker/>
                    { for props.children.iter() }
                </ContextProvider<AnalyticsContext>>
            )
        }
        // otherwise
        (ConsentState::No, false) => props.children.iter().collect(),
    }
}

#[function_component(SegmentPageTracker)]
pub fn segment_page_tracker() -> Html {
    let analytics = use_analytics();

    // trigger whenever it changes from here on
    use_effect_with(analytics, |analytics| {
        log::info!("Creating page tracker");
        let analytics = analytics.clone();

        // trigger once
        analytics.page();

        // and whenver it changes
        let listener = yew_nested_router::History::new().clone().listen(move || {
            analytics.page();
        });

        move || drop(listener)
    });

    html!()
}

pub trait BestLanguage {
    type Target;

    fn get(&self) -> Option<&Self::Target>;
}

impl<T> BestLanguage for Option<&T>
where
    T: BestLanguage,
{
    type Target = T::Target;

    fn get(&self) -> Option<&Self::Target> {
        self.and_then(|value| value.get())
    }
}

impl<T> BestLanguage for LocalizedClaim<T> {
    type Target = T;

    fn get(&self) -> Option<&Self::Target> {
        self.get(None)
    }
}

#[function_component(SegmentIdentify)]
pub fn segment_identify() -> Html {
    let analytics = use_analytics();
    let state = use_auth_state();

    let user = use_state_eq(User::default);

    #[derive(Default, Serialize)]
    struct IdentityTraits {
        #[serde(skip_serializing_if = "Option::is_none")]
        preferred_username: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        given_name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        family_name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        middle_name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        nickname: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        email_verified: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        locale: Option<String>,
    }

    use_effect_with((state, user.clone()), |(state, user)| {
        let claims = claims(state);
        let current = match claims {
            Some(claims) => {
                let traits = IdentityTraits {
                    preferred_username: claims.preferred_username().map(|v| v.to_string()),
                    name: claims.name().get().map(|v| v.to_string()),
                    given_name: claims.given_name().get().map(|v| v.to_string()),
                    family_name: claims.family_name().get().map(|v| v.to_string()),
                    middle_name: claims.middle_name().get().map(|v| v.to_string()),
                    nickname: claims.nickname().get().map(|v| v.to_string()),
                    email: claims.email().map(|v| v.to_string()),
                    email_verified: claims.email_verified().map(|v| v.to_string()),
                    locale: claims.locale().map(|v| v.to_string()),
                };

                User {
                    id: Some((**claims.subject()).to_string()),
                    traits: serde_json::to_value(traits).unwrap_or(json!({})),
                    options: Value::Null,
                }
            }
            None => User::default(),
        };
        user.set(current);
    });

    use_effect_with((analytics, (*user).clone()), |(analytics, user)| {
        log::debug!("User changed: {user:?}");
        analytics.identify(user.clone());
    });

    html!()
}

fn build(write_key: Option<&str>) -> Option<AnalyticsBrowser> {
    write_key.map(|write_key| {
        AnalyticsBrowser::load(Settings {
            write_key: write_key.to_string(),
        })
    })
}

/// Wrap a callback with a tracking call
#[hook]
pub fn use_wrap_tracking<'a, IN, OUT, F, FO, D>(cb: Callback<IN, OUT>, deps: D, f: F) -> Callback<IN, OUT>
where
    IN: 'static,
    OUT: 'static,
    F: Fn(&IN, &D) -> FO + 'static,
    FO: Into<TrackingEvent<'static>> + 'static,
    D: Clone + PartialEq + 'static,
{
    let analytics = use_analytics();

    (*use_memo((cb, (analytics, deps)), |(cb, (analytics, deps))| {
        wrap_tracking(analytics.clone(), cb.clone(), {
            let deps = deps.clone();
            move |value| f(value, &deps)
        })
    }))
    .clone()
}

pub trait WrapTracking {
    type Input;
    type Output;

    fn wrap_tracking<F, FO>(self, analytics: UseAnalytics, f: F) -> Callback<Self::Input, Self::Output>
    where
        F: Fn(&Self::Input) -> FO + 'static,
        FO: Into<TrackingEvent<'static>> + 'static;
}

impl<IN, OUT> WrapTracking for Callback<IN, OUT>
where
    IN: 'static,
    OUT: 'static,
{
    type Input = IN;
    type Output = OUT;

    fn wrap_tracking<F, FO>(self, analytics: UseAnalytics, f: F) -> Callback<Self::Input, Self::Output>
    where
        F: Fn(&IN) -> FO + 'static,
        FO: Into<TrackingEvent<'static>> + 'static,
    {
        wrap_tracking(analytics, self, f)
    }
}

/// Wrap a callback with a tracking call
pub fn wrap_tracking<IN, OUT, F, FO>(analytics: UseAnalytics, callback: Callback<IN, OUT>, f: F) -> Callback<IN, OUT>
where
    IN: 'static,
    OUT: 'static,
    F: Fn(&IN) -> FO + 'static,
    FO: Into<TrackingEvent<'static>> + 'static,
{
    Callback::from(move |value| {
        analytics.track(f(&value).into());
        callback.emit(value)
    })
}

/// Create a tracking callback
#[hook]
pub fn use_tracking<'a, IN, F, FO, D>(f: F, deps: D) -> Callback<IN>
where
    IN: 'static,
    F: Fn(IN, &D) -> FO + 'static,
    FO: Into<TrackingEvent<'static>> + 'static,
    D: PartialEq + 'static,
{
    let analytics = use_analytics();

    use_callback((analytics, deps), move |values, (analytics, deps)| {
        analytics.track(f(values, deps));
    })
}
