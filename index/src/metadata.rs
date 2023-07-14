use serde_json::Value;
use tantivy::schema::Schema;
use tantivy::Document;

/// generated the search metadata from an index document
pub fn doc2metadata(schema: &Schema, doc: &Document) -> Value {
    let data = doc
        .get_sorted_field_values()
        .into_iter()
        .map(|(field, values)| (schema.get_field_entry(field), values))
        .collect::<Vec<_>>();

    serde_json::to_value(data).unwrap_or_default()
}
