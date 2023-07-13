mod details;
mod search;

pub use details::*;
pub use search::*;
use std::borrow::Cow;

use crate::{
    backend::Endpoint,
    components::{common::CardWrapper, severity::Severity, table_wrapper::TableWrapper},
    hooks::use_backend::use_backend,
    pages::{AppRoute, View},
    utils::csaf::{find_product_relations, trace_product},
};
use csaf::{
    definitions::{Branch, Note, NoteCategory, ProductIdT, Reference, ReferenceCategory},
    document::{PublisherCategory, Status},
    product_tree::RelationshipCategory,
    vulnerability::ProductStatus,
    Csaf,
};
use patternfly_yew::prelude::*;
use spog_model::prelude::*;
use std::rc::Rc;
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
                >{ &self.summary.id }</Link<AppRoute>>
            ),
            Column::Title => html!(&self.summary.title),
            Column::Severity => html!(
                <Severity severity={self.summary.severity.clone()} />
            ),
            Column::Revision => self.summary.date.date().to_string().into(),
            Column::Download => html!(if let Some(url) = &self.url {
                <a href={url.as_str().to_string()}>
                    <Button icon={Icon::Download} variant={ButtonVariant::Plain} />
                </a>
            }),
            Column::Vulnerabilities => {
                let l = self.summary.cves.len();
                if l == 0 { "N/A".to_string() } else { l.to_string() }.into()
            }
        }
        .into()
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!( <AdvisoryDetails advisory={Rc::new(self.summary.clone())} />);
        vec![Span::max(html)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(AdvisoryResult)]
pub fn advisory_result(props: &AdvisoryResultProperties) -> Html {
    let backend = use_backend();

    let data = match &props.state {
        UseAsyncState::Ready(Ok(val)) => {
            let data: Vec<AdvisoryEntry> = val
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

    let (entries, onexpand) = use_table_data(MemoizedTableModel::new(Rc::new(data.unwrap_or_default())));

    let header = vec![
        yew::props!(TableColumnProperties<Column> {
            index: Column::Id,
            label: "ID",
            width: ColumnWidth::Percent(15)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Title,
            label: "Title",
            width: ColumnWidth::Percent(55)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Severity,
            label: "Severity",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Revision,
            label: "Revision",
            width: ColumnWidth::Percent(10)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Download,
            label: "Download",
            width: ColumnWidth::Percent(5)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Vulnerabilities,
            label: "Vulnerabilities",
            width: ColumnWidth::Percent(5)
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
                html!( <DescriptionGroup term={note_term(note).to_string()}> { &note.text } </DescriptionGroup> )
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
}

#[function_component(CsafProductStatus)]
pub fn csaf_product_status(props: &CsafProductStatusProperties) -> Html {
    html!(
        if let Some(status) = &props.status {
            <DescriptionList>
                <CsafProductStatusSection title="First Affected" entries={status.first_affected.clone()} csaf={props.csaf.clone()}/>
                <CsafProductStatusSection title="First Fixed" entries={status.first_fixed.clone()} csaf={props.csaf.clone()} />
                <CsafProductStatusSection title="Fixed" entries={status.fixed.clone()} csaf={props.csaf.clone()} />
                <CsafProductStatusSection title="Known Affected" entries={status.known_affected.clone()} csaf={props.csaf.clone()} />
                <CsafProductStatusSection title="Known Not Affected" entries={status.known_not_affected.clone()} csaf={props.csaf.clone()} />
                <CsafProductStatusSection title="Last Affected" entries={status.last_affected.clone()} csaf={props.csaf.clone()} />
                <CsafProductStatusSection title="Recommended" entries={status.recommended.clone()} csaf={props.csaf.clone()} />
                <CsafProductStatusSection title="Under Investigation" entries={status.under_investigation.clone()} csaf={props.csaf.clone()} />
            </DescriptionList>
        }
    )
}

#[derive(PartialEq, Properties)]
pub struct CsafProductStatusSectionProperties {
    pub title: AttrValue,
    pub entries: Option<Vec<ProductIdT>>,
    pub csaf: Rc<Csaf>,
}

#[function_component(CsafProductStatusSection)]
fn csaf_product_status(props: &CsafProductStatusSectionProperties) -> Html {
    html!(
        if let Some(entries) = &props.entries {
            <DescriptionGroup term={&props.title}>
                <List>
                    { for entries.iter().map(|entry|{
                        csaf_product_status_entry(&props.csaf, entry)
                    })}
                </List>
            </DescriptionGroup>
        }
    )
}

fn csaf_product_status_entry(csaf: &Csaf, id: &ProductIdT) -> Html {
    find_product_relations(csaf, id)
        .map(|r| {
            let product = product_html(trace_product(csaf, &r.relates_to_product_reference));
            let relationship = html!(<Label label={rela_cat_str(&r.category)} compact=true />);
            let component = product_html(trace_product(csaf, &r.product_reference));

            html!(<>
                { component } {" "} { relationship } {" "} { product }  
            </>)
        })
        .collect()
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
                { &first.name }
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
