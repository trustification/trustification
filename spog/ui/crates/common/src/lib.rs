pub mod components;
pub mod config;
pub mod error;
pub mod utils;

use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;

#[hook]
pub fn use_apply_pagination<T>(entries: Rc<Vec<T>>, control: PaginationControl) -> Rc<Vec<T>>
where
    T: Clone + PartialEq + 'static,
{
    use_memo((entries, control), |(entries, control)| {
        let offset = control.per_page * control.page;
        let limit = control.per_page;
        entries
            .iter()
            // apply pagination window
            .skip(offset)
            .take(limit)
            .cloned()
            .collect::<Vec<_>>()
    })
}
