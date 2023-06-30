use patternfly_yew::prelude::*;
use yew::prelude::*;

const DEFAULT_HELP: &str = r#"

<p>
When using the <strong>simple</strong> search mode, you can search for words in the name and
description of documents. If you put into multiple words, by default, all words must match.
</p>
<p>
You can use <code>OR</code>, <code>AND</code>, <code>NOT</code>, and parenthesis to change this
behavior.
</p>
<p>
For searching special characters, whitespaces, or for searching for the literal keywords (like entries containing <q>OR</q>), surround the word with double quotes.
</p>

<p>When using the <strong>complex</strong> search mode, you can add additional qualifiers to the search
expression in order to further refine it. Qualifiers have the form of <code>qualifier:&lt;value&gt;</code>.
Multiple values, combines with <q>or</q>, can be provided by using a comma-seperated list, like <code>qualifier:&lt;value1&gt;,&lt;value2&gt;</code>.
</p>

"#;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct SearchHelpPopoverProperties {
    #[prop_or_default]
    pub children: Children,
}

#[function_component(SearchHelpPopover)]
pub fn search_help_popover(props: &SearchHelpPopoverProperties) -> Html {
    let header = html!("Search Help");

    let body = html_nested!(
        <PopoverBody {header}>
            <Content>
                { Html::from_html_unchecked(DEFAULT_HELP.into()) }
            </Content>
            { for props.children.iter() }
        </PopoverBody>
    );

    let target = html!(<span style="cursor: pointer;"> {Icon::QuestionCircle} </span>);
    html!(
        <Popover{body} {target}/>
    )
}
