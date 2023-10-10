use patternfly_yew::prelude::*;
use trustification_api::search::SearchResult;
use yew::prelude::*;
use yew_more_hooks::prelude::UseAsyncState;

pub trait ResultCount {
    fn count_result(&self) -> Option<usize>;
}

impl<T> ResultCount for SearchResult<T> {
    fn count_result(&self) -> Option<usize> {
        self.total
    }
}

impl<T, E> ResultCount for UseAsyncState<T, E>
where
    T: ResultCount,
{
    fn count_result(&self) -> Option<usize> {
        match self {
            UseAsyncState::Ready(Ok(data)) => data.count_result(),
            _ => None,
        }
    }
}

pub fn count_tab_title<T, E>(title: impl AsRef<str>, state: &UseAsyncState<T, E>) -> Html
where
    T: ResultCount,
{
    let badge = match state {
        UseAsyncState::Ready(Ok(data)) => match data.count_result() {
            Some(count) => html!(<> {" "} <Badge> { count } </Badge> </>),
            None => html!(),
        },
        UseAsyncState::Ready(Err(_)) => html!(),
        _ => {
            html!(<> {" "} <Badge read=true> { Icon::InProgress } </Badge></>)
        }
    };

    html!(<> {title.as_ref()} { badge } </>)
}
