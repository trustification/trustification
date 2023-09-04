use patternfly_yew::prelude::*;
use std::collections::BTreeMap;
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq, Properties)]
pub struct RelatedProductsProperties {
    pub products: Rc<BTreeMap<String, Vec<String>>>,
}

#[function_component(RelatedProducts)]
pub fn related_products(props: &RelatedProductsProperties) -> Html {
    html!(
        <Content>
        { for props.products.iter().map(|(state, products)| {
            html!(<>
                <Title level={Level::H3}>{state}</Title>
                <List>
                    { for products.iter().map(Html::from) }
                </List>
            </>)
        })}
        </Content>
    )
}
