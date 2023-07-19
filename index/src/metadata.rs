use serde_json::{json, Value};
use std::collections::BTreeMap;
use tantivy::schema::Schema;
use tantivy::Document;

/// generate the search metadata from an index document
pub fn doc2metadata(schema: &Schema, doc: &Document) -> Value {
    let data = doc
        .get_sorted_field_values()
        .into_iter()
        .map(|(field, values)| {
            let field = schema.get_field_entry(field);
            let value = json!({
                "field": &field,
                "values": &values,
            });
            (field.name(), value)
        })
        .collect::<BTreeMap<_, _>>();

    serde_json::to_value(data).unwrap_or_default()
}
