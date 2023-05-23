use cyclonedx_bom::prelude::Bom;
use patternfly_yew::prelude::*;
use std::collections::BTreeSet;
use std::rc::Rc;
use trust_api_model::prelude::*;
use yew::prelude::*;

#[derive(Clone, PartialEq)]
pub struct UnknownEntry {
    purl: String,
}

impl TableEntryRenderer for UnknownEntry {
    fn render_cell(&self, context: &CellContext) -> Cell {
        match context.column {
            0 => html!({ &self.purl }),
            _ => html!(),
        }
        .into()
    }
}

#[derive(Clone, PartialEq, Properties)]
pub struct UnknownPackagesProperties {
    pub unknown: Rc<Vec<UnknownEntry>>,
}

#[function_component(UnknownPackages)]
pub fn unknown_packages(props: &UnknownPackagesProperties) -> Html {
    let header = html_nested!(
      <TableHeader>
        <TableColumn label="Package URL"/>
        <TableColumn/>
      </TableHeader>
    );

    let entries = use_memo(
        |entries| SharedTableModel::new((**entries).clone()),
        props.unknown.clone(),
    );

    html!(
        <Table<SharedTableModel<UnknownEntry>>
            {header} entries={(*entries).clone()}
            mode={TableMode::Compact}
        >
        </Table<SharedTableModel<UnknownEntry>>>
    )
}

pub fn into_unknown(bom: &Bom, refs: &[PackageRef]) -> Vec<UnknownEntry> {
    let mut components = bom
        .components
        .as_ref()
        .map(|c| {
            c.0.iter()
                .filter_map(|c| c.purl.as_ref().map(|purl| purl.to_string()))
                .collect::<BTreeSet<String>>()
        })
        .unwrap_or_default();

    for found in refs.iter() {
        components.remove(&found.purl);
    }

    components
        .into_iter()
        .map(|purl| UnknownEntry { purl })
        .collect()
}
