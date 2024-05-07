use patternfly_yew::prelude::*;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct PaginationWrappedProperties {
    pub children: Children,
    pub pagination: UsePagination,
    pub total: Option<usize>,
}

#[function_component(PaginationWrapped)]
pub fn pagination_wrapped(props: &PaginationWrappedProperties) -> Html {
    let total = use_state_eq(|| None);

    if let Some(val) = props.total {
        total.set(Some(val))
    }

    html!(
        <>
            <div class="pf-v5-u-p-sm">
                <SimplePagination
                    pagination={props.pagination.clone()}
                    total={*total}
                />
            </div>
            { for props.children.iter() }
            <div class="pf-v5-u-p-sm">
                <SimplePagination
                    pagination={props.pagination.clone()}
                    total={*total}
                    position={PaginationPosition::Bottom}
                />
            </div>
        </>
    )
}
