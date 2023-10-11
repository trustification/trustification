use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct RelatedProductsProperties {
    pub products: Rc<Vec<String>>,
}

#[function_component(RelatedProducts)]
pub fn related_products(props: &RelatedProductsProperties) -> Html {
    html!(
        <Content>
            <List>
                { for props.products.iter().map(Html::from) }
            </List>
        </Content>
    )
}
