use patternfly_yew::prelude::*;
use spog_model::prelude::{PackageDependencies, PackageRef};
use spog_ui_backend::{use_backend, PackageService};
use spog_ui_components::async_state_renderer::async_content;
use std::rc::Rc;
use yew::prelude::*;
use yew_more_hooks::hooks::use_async_with_cloned_deps;
use yew_oauth2::hook::use_latest_access_token;

#[derive(PartialEq, Properties)]
pub struct TreeProperties {
    pub package_id: String,
}

#[function_component(Tree)]
pub fn tree(props: &TreeProperties) -> Html {
    let backend = use_backend();
    let access_token = use_latest_access_token();

    let state = use_async_with_cloned_deps(
        move |package_id| async move {
            let service = PackageService::new(backend.clone(), access_token.clone());
            service
                .dependents(&package_id)
                .await
                .map(Rc::new)
                .map_err(|err| err.to_string())
        },
        props.package_id.clone(),
    );

    html!(
        <>
            {
                async_content(&*state, |state| html!(<ResultContent package={props.package_id.clone()} dependents={state.clone()} />))
            }
        </>
    )
}

#[derive(PartialEq)]
struct Root {
    root: Rc<Node>,
}

#[derive(PartialEq)]
struct Node {
    leaf: String,
    children: Vec<Rc<Node>>,
}

impl TreeTableModel<()> for Root {
    fn children(&self) -> Vec<Rc<dyn TreeNode<()>>> {
        self.root.children()
    }
}

impl TreeNode<()> for Node {
    fn render_cell(&self, _: CellContext<()>) -> Cell {
        html!(<>{&self.leaf}</>).into()
    }

    fn children(&self) -> Vec<Rc<dyn TreeNode<()>>> {
        self.children
            .iter()
            .map(|c| c.clone() as Rc<dyn TreeNode<()>>)
            .collect()
    }
}

fn packageref_to_node(package_ref: &PackageRef) -> Rc<Node> {
    Rc::new(Node {
        leaf: package_ref.purl.clone(),
        children: package_ref.children.iter().map(packageref_to_node).collect(),
    })
}

#[derive(PartialEq, Properties)]
pub struct ResultContentProperties {
    package: String,
    dependents: Rc<PackageDependencies>,
}

#[function_component(ResultContent)]
fn result_content(props: &ResultContentProperties) -> Html {
    let header = html_nested! {
        <TreeTableHeader<()>>
            <TableColumn<()> index={()} label="Purl"/>
        </TreeTableHeader<()>>
    };

    let nodes: Vec<Rc<Node>> = props.dependents.iter().map(packageref_to_node).collect();

    let model = Rc::new(Root {
        root: Rc::new(Node {
            leaf: props.package.clone(),
            children: vec![Rc::new(Node {
                leaf: props.package.clone(),
                children: nodes,
            })],
        }),
    });

    html!(
        <Grid gutter=true>
            <TreeTable<(), Root>
                mode={TreeTableMode::Compact}
                {header}
                {model}
            />
        </Grid>
    )
}
