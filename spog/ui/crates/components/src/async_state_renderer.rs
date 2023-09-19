use patternfly_yew::prelude::*;
use spog_model::search::SearchResult;
use spog_ui_common::error::components::Error;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::UseAsyncState;

#[derive(Clone, PartialEq, Properties)]
pub struct AsyncStateRendererProps<T>
where
    T: Clone + PartialEq,
{
    pub state: UseAsyncState<SearchResult<Rc<Vec<T>>>, String>,
    pub on_ready: Callback<SearchResult<Rc<Vec<T>>>, Html>,
}

#[function_component(AsyncStateRenderer)]
pub fn async_state_renderer<T>(props: &AsyncStateRendererProps<T>) -> Html
where
    T: Clone + PartialEq,
{
    async_content(&props.state, |result| match result.is_empty() {
        true => html!(
            <Bullseye>
                <EmptyState
                    title="No results"
                    icon={Icon::Search}
                >
                    { "Try a different search expression." }
                </EmptyState>
            </Bullseye>
        ),
        false => props.on_ready.emit(result.clone()),
    })
}

pub fn async_content<T, E, F>(state: &UseAsyncState<T, E>, f: F) -> Html
where
    T: Clone + PartialEq,
    E: ToString,
    F: FnOnce(&T) -> Html,
{
    match &state {
        UseAsyncState::Pending | UseAsyncState::Processing => {
            html!( <Bullseye><Spinner/></Bullseye> )
        }
        UseAsyncState::Ready(Ok(result)) => f(result),
        UseAsyncState::Ready(Err(err)) => html!(
            <Error err={err.to_string()}/>
        ),
    }
}
