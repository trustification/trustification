use crate::components::search::{Search, SearchCategory, SearchOption};
use crate::utils::search::{escape_terms, or_group, SimpleProperties, ToFilterExpression};
use spog_model::prelude::Filters;
use std::collections::HashSet;
use std::rc::Rc;
use yew::{AttrValue, Html};

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DynamicSearchParameters {
    terms: Vec<String>,
    state: HashSet<(Rc<String>, Rc<String>)>,
}

impl DynamicSearchParameters {
    pub fn get(&self, cat: Rc<String>, id: Rc<String>) -> bool {
        self.state.contains(&(cat, id))
    }

    pub fn set(&mut self, cat: Rc<String>, id: Rc<String>, value: bool) {
        if value {
            self.state.insert((cat, id));
        } else {
            self.state.remove(&(cat, id));
        }
    }
}

impl SimpleProperties for DynamicSearchParameters {
    fn terms(&self) -> &[String] {
        &self.terms
    }

    fn terms_mut(&mut self) -> &mut Vec<String> {
        &mut self.terms
    }
}

impl ToFilterExpression for DynamicSearchParameters {
    type Context = Filters;

    fn to_filter_expression(&self, context: &Self::Context) -> String {
        let mut terms = escape_terms(self.terms.clone()).collect::<Vec<_>>();

        for cat in &context.categories {
            for opt in &cat.options {
                if self.get(Rc::new(cat.label.clone()), Rc::new(opt.id.clone())) {
                    terms.extend(or_group(opt.terms.clone()));
                }
            }
        }

        terms.join(" ")
    }
}

pub fn convert_search(filters: &Filters) -> Search<DynamicSearchParameters> {
    let categories = filters
        .categories
        .iter()
        .map(|cat| {
            let cat_id = Rc::new(cat.label.clone());
            SearchCategory {
                title: cat.label.clone(),
                options: cat
                    .options
                    .iter()
                    .map(|opt| {
                        let label = format!("<div>{}</div>", opt.label);
                        let cat_id = cat_id.clone();
                        let id = Rc::new(opt.id.clone());
                        SearchOption {
                            label: Html::from_html_unchecked(AttrValue::from(label.clone())).into(),
                            getter: {
                                let cat_id = cat_id.clone();
                                let id = id.clone();
                                Rc::new(move |state: &DynamicSearchParameters| state.get(cat_id.clone(), id.clone()))
                            },
                            setter: {
                                Rc::new(move |state: &mut DynamicSearchParameters, value| {
                                    state.set(cat_id.clone(), id.clone(), value)
                                })
                            },
                        }
                    })
                    .collect(),
            }
        })
        .collect();

    Search { categories }
}
