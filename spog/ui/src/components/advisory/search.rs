use crate::{
    backend::{SearchOptions, VexService},
    components::{search::*, severity::Severity},
    hooks::{use_backend::use_backend, use_standard_search, UseStandardSearch},
    utils::{pagination_to_offset, search::*},
};
use lazy_static::lazy_static;
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::fmt::Debug;
use std::{collections::HashSet, rc::Rc};
use vexination_model::prelude::Vulnerabilities;
use yew::prelude::*;
use yew_more_hooks::prelude::*;

#[derive(PartialEq, Properties)]
pub struct AdvisorySearchProperties {
    pub callback: Callback<UseAsyncHandleDeps<SearchResult<Rc<Vec<AdvisorySummary>>>, String>>,

    pub query: Option<String>,

    #[prop_or_default]
    pub toolbar_items: ChildrenWithProps<ToolbarItem>,

    #[prop_or_default]
    pub children: Children,
}

#[function_component(AdvisorySearch)]
pub fn advisory_search(props: &AdvisorySearchProperties) -> Html {
    let backend = use_backend();

    let service = use_memo(|backend| VexService::new(backend.clone()), backend);

    let total = use_state_eq(|| None);

    let UseStandardSearch {
        search_params,
        pagination,
        filter_input_state,
        onclear,
        onset,
        ontogglesimple,
        text,
    } = use_standard_search::<SearchParameters, Vulnerabilities>(props.query.clone(), *total);

    let search = {
        use_async_with_cloned_deps(
            move |(search_params, page, per_page)| async move {
                service
                    .search_advisories(
                        &search_params.as_str(),
                        &SearchOptions {
                            offset: Some(pagination_to_offset(page, per_page)),
                            limit: Some(per_page),
                        },
                    )
                    .await
                    .map(|result| result.map(Rc::new))
                    .map_err(|err| err.to_string())
            },
            ((*search_params).clone(), pagination.page, pagination.per_page),
        )
    };

    total.set(search.data().and_then(|d| d.total));

    use_effect_with_deps(
        |(callback, search)| {
            callback.emit(search.clone());
        },
        (props.callback.clone(), search.clone()),
    );

    // filter

    let hidden = text.is_empty();
    let filter_expansion = use_state(|| SEARCH.category_labels::<HashSet<_>>());

    // switch

    let simple = search_params.is_simple();

    // render
    html!(
        <>

            <Grid>
                <GridItem cols={[2]}>
                    <SimpleModeSwitch {simple} ontoggle={ontogglesimple} />
                </GridItem>

                <GridItem cols={[10]}>

                    <Toolbar>
                        <ToolbarContent>
                            <ToolbarGroup variant={GroupVariant::Filter}>
                                <ToolbarItem r#type={ToolbarItemType::SearchFilter} width={["600px".to_string()]}>
                                    <Form onsubmit={onset.reform(|_|())}>
                                        // needed to trigger submit when pressing enter in the search field
                                        <input type="submit" hidden=true formmethod="dialog" />
                                        <InputGroup>
                                            <TextInputGroup>
                                                <TextInput
                                                    icon={Icon::Search}
                                                    placeholder="Search"
                                                    value={(*text).clone()}
                                                    state={*filter_input_state}
                                                    oninput={ Callback::from(move |data| text.set(data)) }
                                                />

                                                if !hidden {
                                                    <TextInputGroupUtilities>
                                                        <Button icon={Icon::Times} variant={ButtonVariant::Plain} onclick={onclear} />
                                                    </TextInputGroupUtilities>
                                                }
                                            </TextInputGroup>
                                            <InputGroupItem>
                                                <Button
                                                    disabled={*filter_input_state == InputState::Error}
                                                    icon={Icon::ArrowRight}
                                                    variant={ButtonVariant::Control}
                                                    onclick={onset.reform(|_|())}
                                                />
                                            </InputGroupItem>
                                        </InputGroup>
                                    </Form>
                                </ToolbarItem>

                            </ToolbarGroup>

                            { for props.toolbar_items.iter() }

                            <ToolbarItem r#type={ToolbarItemType::Pagination}>
                                <SimplePagination
                                    pagination={pagination.clone()}
                                    total={*total}
                                />
                            </ToolbarItem>

                        </ToolbarContent>
                    </Toolbar>

                </GridItem>

                <GridItem cols={[2]}>
                    { simple_search(&SEARCH, search_params, filter_expansion) }
                </GridItem>

                <GridItem cols={[10]}>
                    { for props.children.iter() }
                </GridItem>

            </Grid>

            <SimplePagination
                {pagination}
                total={*total}
                position={PaginationPosition::Bottom}
            />

        </>
    )
}

lazy_static! {
    static ref SEARCH: Search<SearchParameters> = Search {
        categories: vec![
            SearchCategory {
                title: "Severity",
                options: vec![
                    SearchOption::<SearchParameters>::new_fn(
                        || html!(<Severity severity="Low"/>),
                        |options| options.is_low,
                        |options, value| options.is_low = value
                    ),
                    SearchOption::<SearchParameters>::new_fn(
                        || html!(<Severity severity="Moderate"/>),
                        |options| options.is_moderate,
                        |options, value| options.is_moderate = value
                    ),
                    SearchOption::<SearchParameters>::new_fn(
                        || html!(<Severity severity="Important"/>),
                        |options| options.is_important,
                        |options, value| options.is_important = value
                    ),
                    SearchOption::<SearchParameters>::new_fn(
                        || html!(<Severity severity="Critical"/>),
                        |options| options.is_critical,
                        |options, value| options.is_critical = value
                    )
                ],
            },
            SearchCategory {
                title: "Products",
                options: vec![
                    SearchOption::<SearchParameters>::new_str(
                        "Red Hat Enterprise Linux 7",
                        |options| options.is_rhel7,
                        |options, value| options.is_rhel7 = value
                    ),
                    SearchOption::<SearchParameters>::new_str(
                        "Red Hat Enterprise Linux 8",
                        |options| options.is_rhel8,
                        |options, value| options.is_rhel8 = value
                    ),
                    SearchOption::<SearchParameters>::new_str(
                        "Red Hat Enterprise Linux 9",
                        |options| options.is_rhel9,
                        |options, value| options.is_rhel9 = value
                    ),
                    SearchOption::<SearchParameters>::new_str(
                        "OpenShift Container Platform 3",
                        |options| options.is_ocp3,
                        |options, value| options.is_ocp3 = value
                    ),
                    SearchOption::<SearchParameters>::new_str(
                        "OpenShift Container Platform 4",
                        |options| options.is_ocp4,
                        |options, value| options.is_ocp4 = value
                    ),
                ]
            }
        ]
    };
}

#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SearchParameters {
    terms: Vec<String>,

    is_low: bool,
    is_moderate: bool,
    is_important: bool,
    is_critical: bool,

    is_rhel7: bool,
    is_rhel8: bool,
    is_rhel9: bool,

    is_ocp3: bool,
    is_ocp4: bool,
}

impl SimpleProperties for SearchParameters {
    fn terms(&self) -> &[String] {
        &self.terms
    }

    fn terms_mut(&mut self) -> &mut Vec<String> {
        &mut self.terms
    }
}

impl ToFilterExpression for SearchParameters {
    fn to_filter_expression(&self) -> String {
        let mut terms = escape_terms(self.terms.clone()).collect::<Vec<_>>();

        {
            let mut severities = vec![];

            if self.is_low {
                severities.push("severity:Low");
            }

            if self.is_moderate {
                severities.push("severity:Moderate");
            }

            if self.is_important {
                severities.push("severity:Important");
            }

            if self.is_critical {
                severities.push("severity:Critical");
            }

            terms.extend(or_group(severities));
        }

        {
            let mut products = vec![];

            if self.is_rhel7 {
                products.push(r#"( "cpe:/o:redhat:rhel_eus:7" in:package )"#);
            }

            if self.is_rhel8 {
                products.push(r#"( "cpe:/a:redhat:rhel_eus:8" in:package )"#);
            }

            if self.is_rhel9 {
                products.push(r#"( "cpe:/a:redhat:enterprise_linux:9" in:package )"#);
            }

            if self.is_ocp3 {
                products.push(r#"( "cpe:/a:redhat:openshift:3" in:package )"#);
            }

            if self.is_ocp4 {
                products.push(r#"( "cpe:/a:redhat:openshift:4" in:package )"#);
            }

            terms.extend(or_group(products));
        }

        terms.join(" ")
    }
}
