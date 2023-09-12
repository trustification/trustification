use crate::components::search::{
    Search, SearchCategory, SearchOption, SearchOptionCheck, SearchOptionSelect, SearchOptionSelectItem,
};
use crate::utils::search::{escape_terms, or_group, SimpleProperties, ToFilterExpression};
use spog_model::prelude::*;
use std::collections::HashMap;
use std::rc::Rc;
use yew::prelude::*;

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DynamicSearchParameters {
    pub terms: Vec<String>,
    pub state: HashMap<(Rc<String>, Rc<String>), Rc<String>>,
    pub sort: Option<(String, bool)>, // Column name and whether or not is ASC
}

impl DynamicSearchParameters {
    pub fn get(&self, cat: Rc<String>, id: Rc<String>) -> Option<Rc<String>> {
        self.state.get(&(cat, id)).cloned()
    }

    pub fn set(&mut self, cat: Rc<String>, id: Rc<String>, value: Option<Rc<String>>) {
        if let Some(value) = value {
            self.state.insert((cat, id), value);
        } else {
            self.state.remove(&(cat, id));
        }
    }

    pub fn set_sort_by(&mut self, sort: (String, bool)) {
        self.sort = Some(sort);
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
            let mut cat_terms = vec![];
            for opt in &cat.options {
                match opt {
                    FilterOption::Divider => {
                        // skip over dividers
                    }
                    FilterOption::Check(opt) => {
                        if self.get(Rc::new(cat.label.clone()), Rc::new(opt.id.clone())).is_some() {
                            cat_terms.extend(opt.terms.clone());
                        }
                    }
                    FilterOption::Select(opt) => {
                        if let Some(id) = self.get(Rc::new(cat.label.clone()), Rc::new(opt.group.clone())) {
                            for o in &opt.options {
                                if o.id == *id {
                                    cat_terms.extend(o.terms.clone());
                                }
                            }
                        }
                    }
                }
            }
            terms.extend(or_group(cat_terms));
        }

        if let Some(sort) = self.sort.clone() {
            let sort_prefix = if sort.1 { "" } else { "-" };
            terms.push(format!("{sort_prefix}sort:{}", sort.0));
        };

        terms.join(" ")
    }
}

pub fn convert_search(filters: &Filters) -> Search<DynamicSearchParameters> {
    let categories = filters
        .categories
        .iter()
        .map(|cat| SearchCategory {
            title: cat.label.clone(),
            options: cat.options.iter().map(|opt| convert_option(&cat.label, opt)).collect(),
        })
        .collect();

    Search { categories }
}

fn convert_option(cat_id: &str, opt: &FilterOption) -> SearchOption<DynamicSearchParameters> {
    let cat_id = Rc::new(cat_id.to_string());

    match opt {
        FilterOption::Divider => SearchOption::Divider,
        FilterOption::Check(opt) => {
            let label = format!("<div>{}</div>", opt.label);
            let id = Rc::new(opt.id.clone());
            SearchOption::Check(SearchOptionCheck::<DynamicSearchParameters> {
                label: Html::from_html_unchecked(AttrValue::from(label.clone())).into(),
                getter: {
                    let cat_id = cat_id.clone();
                    let id = id.clone();
                    Rc::new(move |state| state.get(cat_id.clone(), id.clone()).is_some())
                },
                setter: {
                    Rc::new(move |state, value| {
                        state.set(cat_id.clone(), id.clone(), value.then(|| Rc::new(String::new())))
                    })
                },
            })
        }
        FilterOption::Select(select) => {
            let group = Rc::new(select.group.clone());
            SearchOption::Select(SearchOptionSelect::<DynamicSearchParameters> {
                options: select
                    .options
                    .iter()
                    .map(|option| {
                        let cat_id = cat_id.clone();
                        let group = group.clone();
                        let id = Rc::new(option.id.clone());
                        let label = format!("<div>{}</div>", option.label);
                        SearchOptionSelectItem {
                            label: Html::from_html_unchecked(AttrValue::from(label)).into(),
                            getter: {
                                let cat_id = cat_id.clone();
                                let group = group.clone();
                                let id = id.clone();
                                Rc::new(move |state: &DynamicSearchParameters| {
                                    state.get(cat_id.clone(), group.clone()).as_deref() == Some(&*id)
                                })
                            },
                            setter: {
                                Rc::new(move |state, event_value| {
                                    if event_value {
                                        // we only set the radio button which got set to true, which is the only even we get anyway
                                        state.set(cat_id.clone(), group.clone(), Some(id.clone()));
                                    }
                                })
                            },
                        }
                    })
                    .collect(),
            })
        }
    }
}
