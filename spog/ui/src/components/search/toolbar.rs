use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct SearchToolbarProperties {
    #[prop_or_default]
    pub children: ChildrenWithProps<ToolbarItem>,

    pub text: String,
    pub pagination: UsePagination,
    pub total: Option<usize>,
    pub filter_input_state: Rc<InputState>,

    pub onset: Callback<()>,
    pub onclear: Callback<()>,
    pub onchange: Callback<String>,
}

#[function_component(SearchToolbar)]
pub fn search_toolbar(props: &SearchToolbarProperties) -> Html {
    let hidden = props.text.is_empty();

    html!(
        <Toolbar>
            <ToolbarContent>

                <ToolbarGroup variant={GroupVariant::Filter}>
                    <ToolbarItem r#type={ToolbarItemType::SearchFilter} width={["600px".to_string()]}>
                        <Form onsubmit={props.onset.reform(|_|())}>
                            // needed to trigger submit when pressing enter in the search field
                            <input type="submit" hidden=true formmethod="dialog" />
                            <InputGroup>
                                <TextInputGroup>
                                    <TextInput
                                        icon={Icon::Search}
                                        placeholder="Search"
                                        value={props.text.clone()}
                                        state={*props.filter_input_state}
                                        onchange={props.onchange.clone()}
                                    />

                                    if !hidden {
                                        <TextInputGroupUtilities>
                                            <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={props.onclear.reform(|_|())} />
                                        </TextInputGroupUtilities>
                                    }
                                </TextInputGroup>
                                <InputGroupItem>
                                    <Button
                                        disabled={*props.filter_input_state == InputState::Error}
                                        icon={Icon::ArrowRight}
                                        variant={ButtonVariant::Control}
                                        onclick={props.onset.reform(|_|())}
                                    />
                                </InputGroupItem>
                            </InputGroup>
                        </Form>
                    </ToolbarItem>

                </ToolbarGroup>

                { for props.children.iter() }

                <ToolbarItem r#type={ToolbarItemType::Pagination}>
                    <SimplePagination
                        pagination={props.pagination.clone()}
                        total={props.total}
                    />
                </ToolbarItem>

            </ToolbarContent>
        </Toolbar>
    )
}
