use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use utoipa::{
    openapi::{schema::AdditionalProperties, *},
    ToSchema,
};
use v11y_model::Vulnerability;

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct AnalyzeRequest {
    pub purls: Vec<String>,
}

fn response_affected() -> Object {
    ObjectBuilder::new()
        .schema_type(SchemaType::Object)
        .additional_properties(Some(AdditionalProperties::RefOr(RefOr::T(
            ArrayBuilder::new()
                .items(
                    ObjectBuilder::new()
                        .schema_type(SchemaType::String)
                        .description(Some("vulnerability ID"))
                        .build(),
                )
                .build()
                .into(),
        ))))
        .build()
}

#[derive(PartialEq, Serialize, Deserialize, Debug, Default, Clone, ToSchema)]
pub struct AnalyzeResponse {
    #[schema(schema_with = response_affected)]
    pub affected: HashMap<String, Vec<String>>,
    //#[schema(additional_properties, value_type = Vulnerability)]
    pub vulnerabilities: Vec<Vulnerability>,
    pub errors: Vec<String>,
}

impl AnalyzeResponse {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_package_vulnerability(&mut self, purl: &str, vuln_id: &str) {
        if !self.affected.contains_key(purl) {
            self.affected.insert(purl.to_string(), Vec::new());
        }

        if let Some(inner) = self.affected.get_mut(purl) {
            inner.push(vuln_id.to_string());
        }
    }

    pub fn add_vulnerability(&mut self, vuln: &Vulnerability) {
        self.vulnerabilities.push(vuln.clone());
        //if !self.vulnerabilities.contains_key(&vuln.id) {
        //self.vulnerabilities.insert(vuln.id.clone(), Vec::new());
        //}

        //if let Some(inner) = self.vulnerabilities.get_mut(&vuln.id) {
        //inner.push(vuln.clone())
        //}
    }
}
