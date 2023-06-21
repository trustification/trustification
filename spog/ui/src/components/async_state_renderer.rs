use crate::components::error::Error;
use patternfly_yew::prelude::*;
use spog_model::search::SearchResult;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::UseAsyncState;

#[derive(Clone, Debug, PartialEq)]
struct Theme {}

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
    html!(<>
        {
            match &props.state {
                UseAsyncState::Pending | UseAsyncState::Processing => {
                    html!( <Bullseye><Spinner/></Bullseye> )
                },
                UseAsyncState::Ready(Ok(result)) if result.is_empty() => {
                    html!(
                        <Bullseye>
                            <EmptyState
                                title="No results"
                                icon={Icon::Search}
                            >
                                { "Try a different search expression." }
                            </EmptyState>
                        </Bullseye>
                    )
                },
                UseAsyncState::Ready(Ok(result)) => {
                    props.on_ready.emit(result.clone())
                },
                UseAsyncState::Ready(Err(err)) => html!(
                    <Error err={err.clone()}/>
                ),
            }
        }
        </>
    )
}
