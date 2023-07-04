mod details;
mod search;

pub use details::*;
pub use search::*;
use std::borrow::Cow;

use crate::{
    backend::Endpoint,
    components::{common::CardWrapper, table_wrapper::TableWrapper},
    hooks::use_backend::use_backend,
    pages::{AppRoute, View},
};
use csaf::definitions::ProductIdT;
use csaf::vulnerability::ProductStatus;
use csaf::{
    definitions::{Note, NoteCategory, Reference, ReferenceCategory},
    document::{PublisherCategory, Status},
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
    Revision,
    Download,
    Vulnerabilities,
}

impl TableEntryRenderer<Column> for AdvisoryEntry {
    fn render_cell(&self, context: CellContext<'_, Column>) -> Cell {
        match context.column {
            Column::Id => html!(<>
                <Link<AppRoute>
                    target={AppRoute::Advisory(View::Content{id: self.summary.id.clone()})}
                >{ &self.summary.id }</Link<AppRoute>>
            </>)
            .into(),
            Column::Title => html!(&self.summary.title).into(),
            Column::Revision => {
                let s = if let Ok(s) = self.summary.date.format(&time::format_description::well_known::Rfc3339) {
                    s.to_string()
                } else {
                    self.summary.date.to_string()
                };
                html!(s).into()
            }
            Column::Download => {
                if let Some(url) = &self.url {
                    html!(
                        <a href={url.as_str().to_string()}>
                            <Button icon={Icon::Download} variant={ButtonVariant::Plain} />
                        </a>
                    )
                    .into()
                } else {
                    html!().into()
                }
            }
            Column::Vulnerabilities => {
                let l = self.summary.cves.len();
                html!(if l == 0 {
                    {
                        "N/A"
                    }
                } else {
                    {
                        l.to_string()
                    }
                })
                .into()
            }
        }
    }

    fn render_details(&self) -> Vec<Span> {
        let html = html!(<AdvisoryDetails advisory={Rc::new(self.summary.clone())} />);
        vec![Span::max(html)]
    }

    fn is_full_width_details(&self) -> Option<bool> {
        Some(true)
    }
}

#[function_component(AdvisoryResult)]
pub fn vulnerability_result(props: &AdvisoryResultProperties) -> Html {
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
            width: ColumnWidth::Percent(45)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Revision,
            label: "Revision",
            width: ColumnWidth::Percent(15)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Download,
            label: "Download",
            width: ColumnWidth::Percent(5)
        }),
        yew::props!(TableColumnProperties<Column> {
            index: Column::Vulnerabilities,
            label: "Vulnerabilities",
            width: ColumnWidth::Percent(15)
        }),
    ];

    html!(
        <TableWrapper<Column, UseTableData<Column, MemoizedTableModel<AdvisoryEntry>>>
            loading={&props.state.is_processing()}
            error={props.state.error().map(|val| val.clone())}
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
                                <Label compact=true label={ref_cat_str(&category)} color={Color::Blue} />
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
            { for props.notes.iter().flat_map(|n|n).map(|note| {
                html!( <DescriptionGroup term={note_term(&note).to_string()}> { &note.text } </DescriptionGroup> )
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
    #[prop_or_default]
    pub plain: bool,
}

#[function_component(CsafProductStatus)]
pub fn csaf_product_status(props: &CsafProductStatusProperties) -> Html {
    html!(
        <CardWrapper plain=true title="Product Status">
            if let Some(status) = &props.status {
                <DescriptionList>
                    <CsafProductStatusSection title="First Affected" entries={status.first_affected.clone()} />
                    <CsafProductStatusSection title="First Fixed" entries={status.first_fixed.clone()} />
                    <CsafProductStatusSection title="Fixed" entries={status.fixed.clone()} />
                    <CsafProductStatusSection title="Known Affected" entries={status.known_affected.clone()} />
                    <CsafProductStatusSection title="Known Not Affected" entries={status.known_not_affected.clone()} />
                    <CsafProductStatusSection title="Last Affected" entries={status.last_affected.clone()} />
                    <CsafProductStatusSection title="Recommended" entries={status.recommended.clone()} />
                    <CsafProductStatusSection title="Under Investigation" entries={status.under_investigation.clone()} />
                </DescriptionList>
            }
        </CardWrapper>
    )
}

#[derive(PartialEq, Properties)]
pub struct CsafProductStatusSectionProperties {
    pub title: AttrValue,
    pub entries: Option<Vec<ProductIdT>>,
}

#[function_component(CsafProductStatusSection)]
fn csaf_product_status(props: &CsafProductStatusSectionProperties) -> Html {
    html!(
        if let Some(entries) = &props.entries {
            <DescriptionGroup term={&props.title}>
                <List>
                    { for entries.iter().map(|entry|{
                        html!(<> {&entry.0} </>)
                    })}
                </List>
            </DescriptionGroup>
        }
    )
}
