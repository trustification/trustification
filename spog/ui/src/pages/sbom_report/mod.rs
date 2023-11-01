//! The SBOM report page

mod details;

use convert_case::{Case, Casing};
use details::Details;
use patternfly_yew::prelude::*;
use serde_json::{json, Value};
use spog_model::prelude::SummaryEntry;
use spog_ui_backend::use_backend;
use spog_ui_common::error::components::Error;
use spog_ui_components::{
    common::{NotFound, PageHeading},
    time::Date,
};
use spog_ui_donut::Donut;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::prelude::*;
use yew_oauth2::prelude::*;

#[derive(Clone, Debug, PartialEq, Properties)]
pub struct SbomReportProperties {
    pub id: String,
}

fn as_float(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) if n.is_f64() => n.as_f64(),
        Value::Number(n) if n.is_i64() => n.as_i64().map(|i| i as _),
        Value::Number(n) if n.is_u64() => n.as_u64().map(|i| i as _),
        _ => None,
    }
}

#[function_component(SbomReport)]
pub fn sbom(props: &SbomReportProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let info = use_async_with_cloned_deps(
        |(id, backend)| async move {
            spog_ui_backend::SBOMService::new(backend.clone(), access_token)
                .get_sbom_vulns(id)
                .await
                .map(|r| r.map(Rc::new))
        },
        (props.id.clone(), backend),
    );

    let labels = use_callback((), |value: Value, ()| {
        let x = &value["datum"]["x"];
        let y = &value["datum"]["y"];

        match (x.as_str(), as_float(y)) {
            (Some(x), Some(y)) => format!("{x}: {y}"),
            _ => "Unknown".to_string(),
        }
    });

    match &*info {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(
            <>
                // <PageHeading>{ props.id.clone() }</PageHeading>
                <PageSection fill={PageSectionFill::Fill}><Spinner/></PageSection>
            </>
        ),
        UseAsyncState::Ready(Ok(None)) => html!(
            <>
                <PageHeading sticky=false>{ props.id.clone() } {" "} </PageHeading>
                <NotFound/>
            </>
        ),
        UseAsyncState::Ready(Ok(Some(data))) => {
            let options = donut_options(data);

            html!(
                <>
                    // <PageSection variant={PageSectionVariant::Light} r#type={PageSectionType::Breadcrumbs}>
                    //     <Content>
                    //         <Title>{ data.name.clone() }</Title>
                    //     </Content>
                    // </PageSection>
                    <Stack gutter=true>
                        <StackItem>
                            <Card>
                                <CardBody>
                                    <Split gutter=true>
                                        <SplitItem fill=true>
                                            <Donut {options} {labels} style="width: 350px;" />
                                        </SplitItem>
                                        <SplitItem>
                                            <DescriptionList auto_fit=true>
                                                if let Some(version) = data.version.clone() {
                                                    <DescriptionGroup term="Version">{ version }</DescriptionGroup>
                                                }
                                                if let Some(timestamp) = data.created {
                                                    <DescriptionGroup term="Creation date"><Date {timestamp} /></DescriptionGroup>
                                                }
                                            </DescriptionList>
                                        </SplitItem>
                                    </Split>
                                </CardBody>
                            </Card>
                        </StackItem>
                        <StackItem>
                            <Details sbom={data.clone()}/>
                        </StackItem>
                    </Stack>
                </>
            )
        }
        UseAsyncState::Ready(Err(err)) => html!(
            <>
                <PageHeading>{ props.id.clone() }</PageHeading>
                <PageSection fill={PageSectionFill::Fill}><Error err={err.to_string()} /></PageSection>
            </>
        ),
    }
}

/// build the options for the donut chart
fn donut_options(data: &spog_model::vuln::SbomReport) -> Value {
    let mut summary = data.summary.clone();

    // reverse sort
    summary.sort_unstable_by(|a, b| b.severity.cmp(&a.severity));

    let total: usize = summary.iter().map(|SummaryEntry { count, .. }| *count).sum();
    let donut_data = summary
        .iter()
        .map(|SummaryEntry { severity, count }| {
            json!({
                "x": severity.map(|k| k.as_str().to_case(Case::Title)).unwrap_or_else(|| "Unknown".to_string()),
                "y": count,
            })
        })
        .collect::<Vec<_>>();

    let legend_data = summary
        .iter()
        .map(|SummaryEntry { severity, count }| {
            let k = severity
                .map(|k| k.as_str().to_case(Case::Title))
                .unwrap_or_else(|| "Unknown".to_string());
            json!({
                "name": format!("{count} {k}"),
            })
        })
        .collect::<Vec<_>>();

    let color_scale = summary
        .iter()
        .map(|SummaryEntry { severity, .. }| match severity {
            None => "var(--pf-v5-global--Color--light-200)",
            Some(cvss::Severity::None) => "var(--pf-v5-global--Color--light-300)",
            Some(cvss::Severity::Low) => "var(--pf-v5-global--info-color--100)",
            Some(cvss::Severity::Medium) => "var(--pf-v5-global--warning-color--100)",
            Some(cvss::Severity::High) => "var(--pf-v5-global--danger-color--100)",
            Some(cvss::Severity::Critical) => "var(--pf-v5-global--palette--purple-400)",
        })
        .collect::<Vec<_>>();

    json!({
        "ariaDesc": "Vulnerabilities summary",
        "ariaTitle": "Vulnerabilities",
        "constrainToVisibleArea": true,
        "data": donut_data,
        "colorScale": color_scale,
        "legendData": legend_data,
        "legendOrientation": "vertical",
        "legendPosition": "right",
        "name": "vulnerabilitiesSummary",
        "padding": { "bottom": 20, "left": 20, "right": 140, "top": 20 },
        "subTitle": "Total vulnerabilities",
        "title": format!("{total}"),
        "width": 350,
    })
}
