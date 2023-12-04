/// Helper to create a typed tracking event
#[macro_export]
macro_rules! tracking_event {
    ($name:ident: $event:literal => $payload:expr ) => {
        pub struct $name;

        impl From<$name> for analytics_next::TrackingEvent<'static> {
            fn from(_: $name) -> Self {
                ($event, $payload).into()
            }
        }
    };
}
