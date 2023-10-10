mod details;
mod search;

pub use details::*;
pub use search::*;

use crate::{
    common::CardWrapper, cvss::CvssMap, download::Download, markdown::Markdown, severity::Severity,
    table_wrapper::TableWrapper,
};
use csaf::{
    definitions::{Branch, Note, NoteCategory, ProductIdT, Reference, ReferenceCategory},
    document::{PublisherCategory, Status},
    product_tree::RelationshipCategory,
    vulnerability::{ProductStatus, RemediationCategory},
    Csaf,
};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use spog_ui_backend::{use_backend, Endpoint};
use spog_ui_common::utils::{
    csaf::{find_product_relations, has_product, trace_product},
    time::date,
};
use spog_ui_navigation::{AppRoute, View};
use std::borrow::Cow;
use std::collections::HashSet;
use std::rc::Rc;
use trustification_api::search::SearchResult;
use url::Url;
use yew::prelude::*;
use yew_more_hooks::prelude::UseAsyncState;
use yew_nested_router::components::Link;

#[derive(PartialEq, Properties, Clone)]
pub struct AdvisoryEntry {
    summary: AdvisorySummary,
    url: Option<Url>,
}

#[derive(PartialEq, Properties)]
pub struct AdvisoryResultProperties {
    pub state: UseAsyncState<SearchResult<Rc<Vec<AdvisorySummary>>>, String>,
    pub onsort: Callback<(String, bool)>,
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Column {
    Id,
    Title,
    Severity,
    Revision,
    Download,
    Vulnerabilities,
}

impl TableEntryRenderer<Column> for AdvisoryEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(
                <Link<AppRoute>
                    target={AppRoute::Advisory(View::Content{id: self.summary.id.clone()})}
                >{ self.summary.id.clone() }</Link<AppRoute>>
            ),
            Column::Title => html!(&self.summary.title),
            Column::Severity => html!(
                <Severity severity={self.summary.severity.clone()} />
            ),
            Column::Revision => date(self.summary.date),
            Column::Download => html!(if let Some(url) = &self.url {
                <Download href={url.clone()} />
            }),
            Column::Vulnerabilities => {
                let l = self.summary.cves.len();
                if l == 0 {
                    "N/A".to_string().into()
                } else {
                    html!(<CvssMap map={self.summary.cve_severity_count.clone()} />)
                }
            }
        }
        .into()
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!( <AdvisoryDetails advisory={Rc::new(self.summary.clone())} />);
        vec![Span::max(html)]
    }
}

#[function_component(AdvisoryResult)]
pub fn advisory_result(props: &AdvisoryResultProperties) -> Html {
    let backend = use_backend();

    let data = match &props.state {
        UseAsyncState::Ready(Ok(val)) => {
            let data: Vec<_> = val
                .result
                .iter()
                .map(|summary| {
                    let url = backend.join(Endpoint::Api, &summary.href).ok();
                    AdvisoryEntry {
                        summary: summary.clone(),
                        url,
                    }
                })
                .collect();
            Some(data)
        }
        _ => None,
    };

    let sortby: UseStateHandle<Option<TableHeaderSortBy<Column>>> = use_state_eq(|| None);
    let onsort = use_callback(
        (sortby.clone(), props.onsort.clone()),
        |val: TableHeaderSortBy<Column>, (sortby, onsort)| {
            sortby.set(Some(val));
            if val.index == Column::Severity {
                onsort.emit(("severity".to_string(), val.asc));
            };
        },
    );

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new(data.unwrap_or_default())));

    let header = vec![
        yew::props!(TableColumnProperties<Column> {
            index: Column::Id,
            label: "ID",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Title,
            label: "Title",
            width: ColumnWidth::Percent(50)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Severity,
            label: "Aggregated Severity",
            width: ColumnWidth::Percent(10),
            text_modifier: Some(TextModifier::Wrap),
            sortby: *sortby,
            onsort: onsort.clone()
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Revision,
            label: "Revision",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Vulnerabilities,
            label: "Vulnerabilities",
            width: ColumnWidth::Percent(20)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Download,
            label: "Download",
            width: ColumnWidth::FitContent
        }),
    ];

    html!(
        <TableWrapper<Column, UseTableData<Column, MemoizedTableModel<AdvisoryEntry>>>
            loading={&props.state.is_processing()}
            error={props.state.error().cloned()}
            empty={entries.is_empty()}
            {header}
        >
            <Table<Column, UseTableData<Column, MemoizedTableModel<AdvisoryEntry>>>
                {entries}
                mode={TableMode::Expandable}
                {onexpand}
            />
        </TableWrapper<Column, UseTableData<Column, MemoizedTableModel<AdvisoryEntry>>>>
    )
}

pub fn cat_label(cat: &PublisherCategory) -> &'static str {
    match cat {
        PublisherCategory::Other => "Other",
        PublisherCategory::Coordinator => "Coordinator",
        PublisherCategory::Discoverer => "Discoverer",
        PublisherCategory::Translator => "Translator",
        PublisherCategory::User => "User",
        PublisherCategory::Vendor => "Vendor",
    }
}

pub fn tracking_status_str(status: &Status) -> &'static str {
    match status {
        Status::Draft => "Draft",
        Status::Interim => "Interim",
        Status::Final => "Final",
    }
}

#[derive(PartialEq, Properties)]
pub struct CsafReferencesProperties {
    pub references: Option<Vec<Reference>>,

    #[prop_or_default]
    pub plain: bool,
}

#[function_component(CsafReferences)]
pub fn csaf_references(props: &CsafReferencesProperties) -> Html {
    html!(
        <CardWrapper plain={props.plain} title="References">
            if let Some(references) = &props.references {
                <List>
                    { for references.iter().map(|reference| {
                        html! ( <>
                            <a class="pf-v5-c-button pf-m-link" href={reference.url.to_string()} target="_blank">
                                { &reference.summary }
                                <span class="pf-v5-c-button__icon pf-m-end">
                                    { Icon::ExternalLinkAlt }
                                </span>
                            </a>
                            if let Some(category) = &reference.category {
                                <Label compact=true label={ref_cat_str(category)} color={Color::Blue} />
                            }
                        </>)
                    }) }
                </List>
            }
        </CardWrapper>
    )
}

pub fn ref_cat_str(category: &ReferenceCategory) -> &'static str {
    match category {
        ReferenceCategory::External => "external",
        ReferenceCategory::RefSelf => "self",
    }
}

#[derive(PartialEq, Properties)]
pub struct CsafNotesProperties {
    pub notes: Option<Vec<Note>>,

    #[prop_or_default]
    pub plain: bool,
}

#[function_component(CsafNotes)]
pub fn csaf_notes(props: &CsafNotesProperties) -> Html {
    html!(
        <CardWrapper plain={props.plain} title="Notes">
            <DescriptionList>
                { for props.notes.iter().flatten().map(|note| {
                    html!(
                        <DescriptionGroup
                            term={note_term(note).to_string()}
                        >
                            <Content>
                                <Markdown content={Rc::new(note.text.clone())}/>
                            </Content>
                        </DescriptionGroup>
                    )
                })}
            </DescriptionList>
        </CardWrapper>
    )
}

fn note_term(note: &Note) -> Cow<str> {
    match &note.title {
        Some(title) => format!("{title} ({})", note_cat_str(&note.category)).into(),
        None => note_cat_str(&note.category).into(),
    }
}

fn note_cat_str(category: &NoteCategory) -> &'static str {
    match category {
        NoteCategory::Description => "Description",
        NoteCategory::Details => "Details",
        NoteCategory::Faq => "FAQ",
        NoteCategory::General => "General",
        NoteCategory::LegalDisclaimer => "Legal Disclaimer",
        NoteCategory::Other => "Other",
        NoteCategory::Summary => "Summary",
    }
}

#[derive(PartialEq, Properties)]
pub struct CsafProductStatusProperties {
    pub status: Option<ProductStatus>,
    pub csaf: Rc<Csaf>,
    pub overview: bool,
}

#[function_component(CsafProductStatus)]
pub fn csaf_product_status(props: &CsafProductStatusProperties) -> Html {
    html!(
        if let Some(status) = &props.status {
            <DescriptionList>
                <CsafProductStatusSection title="First Affected" entries={status.first_affected.clone()} csaf={props.csaf.clone()} overview={props.overview} />
                <CsafProductStatusSection title="First Fixed" entries={status.first_fixed.clone()} csaf={props.csaf.clone()} overview={props.overview} />
                <CsafProductStatusSection title="Fixed" entries={status.fixed.clone()} csaf={props.csaf.clone()} overview={props.overview} />
                <CsafProductStatusSection title="Known Affected" entries={status.known_affected.clone()} csaf={props.csaf.clone()} overview={props.overview} />
                <CsafProductStatusSection title="Known Not Affected" entries={status.known_not_affected.clone()} csaf={props.csaf.clone()} overview={props.overview} />
                <CsafProductStatusSection title="Last Affected" entries={status.last_affected.clone()} csaf={props.csaf.clone()} overview={props.overview} />
                <CsafProductStatusSection title="Recommended" entries={status.recommended.clone()} csaf={props.csaf.clone()} overview={props.overview} />
                <CsafProductStatusSection title="Under Investigation" entries={status.under_investigation.clone()} csaf={props.csaf.clone()} overview={props.overview} />
            </DescriptionList>
        }
    )
}

#[derive(PartialEq, Properties)]
pub struct CsafProductStatusSectionProperties {
    pub title: AttrValue,
    pub entries: Option<Vec<ProductIdT>>,
    pub csaf: Rc<Csaf>,
    pub overview: bool,
}

#[function_component(CsafProductStatusSection)]
fn csaf_product_status(props: &CsafProductStatusSectionProperties) -> Html {
    html!(
        if let Some(entries) = &props.entries {
            <DescriptionGroup term={&props.title}>
                <List>
                    {
                        match props.overview {
                            false => entries.iter().map(|entry| {
                                    csaf_product_status_entry_details(&props.csaf, entry)
                                }).collect::<Vec<_>>(),
                            true => csaf_product_status_entry_overview(&props.csaf, entries),
                        }
                    }
                </List>
            </DescriptionGroup>
        }
    )
}

#[derive(Debug, Eq, PartialEq, Hash)]
enum Product<'a> {
    Known(&'a str),
    Invalid(&'a str),
}

fn csaf_resolve_aggregated_products<'a>(csaf: &'a Csaf, entries: &'a [ProductIdT]) -> HashSet<Product<'a>> {
    // gather unique set of products
    let products = entries.iter().map(|id| id.0.as_str()).collect::<HashSet<_>>();

    // gather unique set of products they relate to
    products
        .into_iter()
        .flat_map(|id| {
            let mut products = find_product_relations(csaf, id)
                .map(|rel| rel.relates_to_product_reference.0.as_str())
                .collect::<Vec<_>>();

            if has_product(csaf, id) {
                products.push(id.clone());
            }

            if products.is_empty() {
                vec![Product::Invalid(id)]
            } else {
                products.into_iter().map(Product::Known).collect::<Vec<_>>()
            }
        })
        .collect::<HashSet<_>>()
}

fn csaf_product_status_entry_overview(csaf: &Csaf, entries: &[ProductIdT]) -> Vec<Html> {
    let products = csaf_resolve_aggregated_products(csaf, entries);

    // render out first segment of those products
    products
        .into_iter()
        .map(|product| match product {
            Product::Known(id) => {
                let mut prod = trace_product(csaf, id);
                html!({ for prod.pop().map(|branch| Html::from(&branch.name)) })
            }
            Product::Invalid(id) => render_invalid_product(id),
        })
        .collect()
}

fn csaf_product_status_entry_details(csaf: &Csaf, id: &ProductIdT) -> Html {
    // for details, we show the actual component plus where it comes from
    let actual = has_product(csaf, &id.0).then_some(id.0.as_str());
    let content = find_product_relations(csaf, &id.0)
        .map(|r| {
            // add product references
            let product = product_html(trace_product(csaf, &r.relates_to_product_reference.0));
            let relationship = html!(<Label label={rela_cat_str(&r.category)} compact=true />);
            let component = product_html(trace_product(csaf, &r.product_reference.0));

            html!(<>
                { component } {" "} { relationship } {" "} { product }  
            </>)
        })
        .chain(actual.map(|product| {
            // add the direct product
            product_html(trace_product(csaf, product))
        }))
        .collect::<Vec<_>>();

    if content.is_empty() {
        render_invalid_product(&id.0)
    } else {
        Html::from_iter(content)
    }
}

fn render_invalid_product(id: &str) -> Html {
    let title = format!(r#"Invalid product ID: "{}""#, id);
    html!(<Alert {title} r#type={AlertType::Warning} plain=true inline=true />)
}

fn product_html(mut branches: Vec<&Branch>) -> Html {
    if let Some(first) = branches.pop() {
        branches.reverse();
        let text = branches
            .into_iter()
            .map(|b| b.name.clone())
            .collect::<Vec<_>>()
            .join(" » ");
        html! (
            <Tooltip {text}>
                { first.name.clone() }
            </Tooltip>
        )
    } else {
        html!()
    }
}

fn rela_cat_str(category: &RelationshipCategory) -> &'static str {
    match category {
        RelationshipCategory::DefaultComponentOf => "default component of",
        RelationshipCategory::ExternalComponentOf => "external component of",
        RelationshipCategory::InstalledOn => "installed on",
        RelationshipCategory::InstalledWith => "installed with",
        RelationshipCategory::OptionalComponentOf => "optional component of",
    }
}

fn rem_cat_str(remediation: &RemediationCategory) -> &'static str {
    match remediation {
        RemediationCategory::Mitigation => "mitigation",
        RemediationCategory::NoFixPlanned => "no fix planned",
        RemediationCategory::NoneAvailable => "none available",
        RemediationCategory::VendorFix => "vendor fix",
        RemediationCategory::Workaround => "workaround",
    }
}

#[allow(unused)]
fn branch_html(branches: Vec<&Branch>) -> Html {
    branches
        .iter()
        .rev()
        .enumerate()
        .map(|(n, branch)| {
            html!(<>
                if n > 0 {
                    { " » "}
                }
                {&branch.name} {" "}
            </>)
        })
        .collect()
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_quarkus_product_id_1() {
        let csaf: Csaf = serde_json::from_slice(include_bytes!("../../../test-data/quarkus1.json")).unwrap();

        let vul1 = &csaf.vulnerabilities.as_ref().unwrap()[0];
        let fixed1 = vul1.product_status.as_ref().unwrap().fixed.as_ref().unwrap();
        let prod1 = &fixed1[0];
        assert_eq!(prod1.0, "Red Hat build of Quarkus");

        assert!(has_product(&csaf, &prod1.0));

        let resolved = csaf_resolve_aggregated_products(&csaf, fixed1);
        assert_eq!(
            Vec::from_iter(resolved),
            vec![Product::Known("Red Hat build of Quarkus")]
        );
    }
}
