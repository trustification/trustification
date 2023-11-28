use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use utoipa::{
    openapi::{schema::AdditionalProperties, *},
    ToSchema,
};

//use v11y_model::Vulnerability;

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

#[derive(Serialize, Deserialize, Debug, Default, Clone, ToSchema)]
pub struct RecommendResponse {
    pub recommendations: HashMap<String, Vec<String>>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, ToSchema)]
pub struct AnalyzeResponse {
    #[schema(schema_with = response_affected)]
    pub analysis: HashMap<String, Vec<VendorAnalysis>>,
    //#[schema(additional_properties, value_type = Vulnerability)]
    pub cves: Vec<Box<RawValue>>,
    pub errors: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, ToSchema)]
pub struct VendorAnalysis {
    pub vendor: String,
    pub vulnerable: Vec<VulnerabilityAnalysis>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certified: Option<PackageCertification>,
    pub recommendations: Vec<String>,
}

impl VendorAnalysis {
    pub fn add_package_vulnerabilities(&mut self, vuln_ids: Vec<String>) {
        for vuln_id in vuln_ids {
            self.vulnerable.push(VulnerabilityAnalysis {
                id: vuln_id,
                severity: vec![],
                aliases: vec![],
            });
        }
    }

    pub fn add_vulnerability_severity(
        &mut self,
        vuln_id: String,
        source: String,
        score_type: String,
        score_value: f64,
    ) {
        if let Some(vuln_analysis) = self.vulnerable.iter_mut().find(|e| e.id == vuln_id) {
            vuln_analysis.add_severity(source, score_type, score_value)
        }
    }

    pub fn add_vulnerability_aliases(&mut self, vuln_id: String, aliases: Vec<String>) {
        if let Some(vuln_analysis) = self.vulnerable.iter_mut().find(|e| e.id == vuln_id) {
            vuln_analysis.add_aliases(aliases)
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, ToSchema)]
pub struct VulnerabilityAnalysis {
    pub id: String,
    pub severity: Vec<SeverityAnalysis>,
    pub aliases: Vec<String>,
}

impl VulnerabilityAnalysis {
    pub fn add_severity(&mut self, source: String, score_type: String, score_value: f64) {
        self.severity.push(SeverityAnalysis {
            source,
            r#type: score_type,
            score: score_value,
        });
    }

    pub fn add_aliases(&mut self, aliases: Vec<String>) {
        for alias in aliases {
            if self.id != alias && !self.aliases.contains(&alias) {
                self.aliases.push(alias);
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub struct SeverityAnalysis {
    pub source: String,
    pub r#type: String,
    pub score: f64,
}

#[derive(Serialize, Deserialize, Debug, Clone, ToSchema)]
pub enum SeverityType {
    CVSSv3,
    CVSSv31,
    CVSSv4,
}

impl AnalyzeResponse {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_package_vulnerabilities(&mut self, purl: String, vendor: String, vuln_ids: Vec<String>) {
        if !self.analysis.contains_key(&purl) {
            self.analysis.insert(purl.clone(), vec![]);
        }

        if let Some(vendor_analyses) = self.analysis.get_mut(&purl) {
            if !vendor_analyses.iter().any(|each| each.vendor == vendor) {
                let analysis = VendorAnalysis {
                    vendor: vendor.clone(),
                    vulnerable: vec![],
                    certified: None,
                    recommendations: vec![],
                };
                vendor_analyses.push(analysis);
            }

            if let Some(vendor_analysis) = vendor_analyses.iter_mut().find(|each| each.vendor == vendor) {
                vendor_analysis.add_package_vulnerabilities(vuln_ids);
            }
        }
    }

    pub fn add_vulnerability_severity(
        &mut self,
        purl: String,
        vendor: String,
        vuln_id: String,
        source: String,
        score_type: String,
        score_value: f64,
    ) {
        if !self.analysis.contains_key(&purl) {
            self.analysis.insert(purl.clone(), vec![]);
        }

        if let Some(vendor_analyses) = self.analysis.get_mut(&purl) {
            if !vendor_analyses.iter().any(|each| each.vendor == vendor) {
                let analysis = VendorAnalysis {
                    vendor: vendor.clone(),
                    vulnerable: vec![],
                    certified: None,
                    recommendations: vec![],
                };
                vendor_analyses.push(analysis);
            }

            if let Some(vendor_analysis) = vendor_analyses.iter_mut().find(|each| each.vendor == vendor) {
                vendor_analysis.add_vulnerability_severity(vuln_id, source, score_type, score_value)
            }
        }
    }

    pub fn add_vulnerability_aliases(&mut self, purl: String, vendor: String, vuln_id: String, aliases: Vec<String>) {
        if !self.analysis.contains_key(&purl) {
            self.analysis.insert(purl.clone(), vec![]);
        }

        if let Some(vendor_analyses) = self.analysis.get_mut(&purl) {
            if !vendor_analyses.iter().any(|each| each.vendor == vendor) {
                let analysis = VendorAnalysis {
                    vendor: vendor.clone(),
                    vulnerable: vec![],
                    certified: None,
                    recommendations: vec![],
                };
                vendor_analyses.push(analysis);
            }

            if let Some(vendor_analysis) = vendor_analyses.iter_mut().find(|each| each.vendor == vendor) {
                vendor_analysis.add_vulnerability_aliases(vuln_id, aliases)
            }
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default, Clone, ToSchema)]
pub struct PackageCertification {
    pub good: bool,
    pub bad: bool,
}
