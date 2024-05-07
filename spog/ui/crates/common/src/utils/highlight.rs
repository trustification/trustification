use yew::prelude::*;

pub fn highlight(value: &str, substring: &str) -> Html {
    html! (
        <span class="tc-c-highlight">
        { for value.split(substring).enumerate().map(|(n, t)| {
            html! (
                <span class="tc-c-highlight">
                    if n > 0 {
                        <span class="tc-c-highlight__match">{ substring }</span>
                    }
                    <span>{ t }</span>
                </span>
            )
        })}
        </span>
    )
}
