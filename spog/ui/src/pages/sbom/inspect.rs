use super::{
    unknown::{into_unknown, UnknownPackages},
    CommonHeader,
};
use crate::{
    backend::PackageService,
    components::{count_title, deps::PackageReferences},
    hooks::use_backend,
};
use cyclonedx_bom::prelude::Bom;
use packageurl::PackageUrl;
use patternfly_yew::prelude::*;
use std::rc::Rc;
use std::str::FromStr;
use yew::prelude::*;
use yew_more_hooks::hooks::r#async::*;

#[derive(Clone, PartialEq, Properties)]
pub struct InspectProperties {
    pub raw: Rc<String>,
    pub bom: Rc<Bom>,
}

#[function_component(Inspect)]
pub fn inspect(props: &InspectProperties) -> Html {
    let tab = use_state_eq(|| 0);
    let onselect = {
        let tab = tab.clone();
        Callback::from(move |index: usize| {
            tab.set(index);
        })
    };

    let purls = use_memo(
        |sbom| match &sbom.components {
            Some(comps) => comps
                .0
                .iter()
                .filter_map(|c| c.purl.as_ref().map(|p| p.to_string()))
                .collect(),
            None => vec![],
        },
        props.bom.clone(),
    );

    let backend = use_backend();

    let service = use_memo(
        |backend| PackageService::new((**backend).clone()),
        backend.clone(),
    );

    let fetch = {
        let service = service.clone();
        use_async_with_cloned_deps(
            |purls| async move {
                service
                    .search(
                        purls
                            .iter()
                            .filter_map(|purl| PackageUrl::from_str(purl).ok()),
                    )
                    .await
            },
            purls.clone(),
        )
    };

    let unknown = use_memo(
        |(f, bom)| match f {
            Some(data) => into_unknown(&bom, data),
            None => vec![],
        },
        (fetch.data().cloned(), props.bom.clone()),
    );

    match &*fetch {
        UseAsyncState::Pending | UseAsyncState::Processing => html!(
            <PageSection fill={PageSectionFill::Fill}>
                <Spinner />
            </PageSection>
        ),
        UseAsyncState::Ready(Ok(data)) => html!(
            <>
                <CommonHeader />

                <PageSection r#type={PageSectionType::Tabs} variant={PageSectionVariant::Light} sticky={[PageSectionSticky::Top]}>
                    <Tabs inset={TabInset::Page} detached=true {onselect}>
                        <Tab label={count_title(data.len(), "Found", "Found")} />
                        <Tab label={count_title(unknown.len(), "Unknown", "Unknown")} />
                        <Tab label="Raw SBOM"/>
                    </Tabs>
                </PageSection>

                <PageSection hidden={*tab != 0} fill={PageSectionFill::Fill}>
                    <PackageReferences refs={data.0.clone()} />
                </PageSection>

                <PageSection hidden={*tab != 1} fill={PageSectionFill::Fill}>
                    <UnknownPackages {unknown} />
                </PageSection>

                <PageSection hidden={*tab != 2} variant={PageSectionVariant::Light} fill={PageSectionFill::Fill}>
                    <CodeBlock>
                        <CodeBlockCode>
                            { &props.raw }
                        </CodeBlockCode>
                    </CodeBlock>
               </PageSection>
            </>
        ),
        UseAsyncState::Ready(Err(err)) => html!(<>{"Failed to load: "} { err } </>),
    }
}
