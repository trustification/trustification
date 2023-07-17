use crate::components::advisory::CsafProperties;
use csaf::definitions::Branch;
use csaf::product_tree::ProductTree;
use patternfly_yew::prelude::*;
use std::rc::Rc;
use yew::prelude::*;

#[derive(PartialEq)]
struct ProductTreeWrapper(ProductTree);

struct BranchWrapper(Branch);

impl TreeTableModel<()> for ProductTreeWrapper {
    fn children(&self) -> Vec<Rc<dyn TreeNode<()>>> {
        self.0
            .branches
            .iter()
            .flat_map(|s| s.0.iter())
            .map(|branch| Rc::new(BranchWrapper(branch.clone())) as Rc<dyn TreeNode<()>>)
            .collect()
    }
}

impl TreeNode<()> for BranchWrapper {
    fn render_cell(&self, _ctx: CellContext<'_, ()>) -> Cell {
        html!(<>
                { &self.0.name } { " " }
                <Label color={Color::Blue} label={format!("{:?}", self.0.category)} outline=true compact=true/>
            </>)
        .into()
    }

    fn children(&self) -> Vec<Rc<dyn TreeNode<()>>> {
        self.0
            .branches
            .iter()
            .flat_map(|s| s.0.iter())
            .map(|branch| Rc::new(BranchWrapper(branch.clone())) as Rc<dyn TreeNode<()>>)
            .collect()
    }
}

#[function_component(CsafProductInfo)]
pub fn product_info(props: &CsafProperties) -> Html {
    use patternfly_yew::prelude::TableColumn;

    let model = use_memo(
        |csaf| {
            ProductTreeWrapper(csaf.product_tree.clone().unwrap_or(ProductTree {
                branches: None,
                product_groups: None,
                full_product_names: None,
                relationships: None,
            }))
        },
        props.csaf.clone(),
    );

    let header = html_nested! {
        <TreeTableHeader<()>>
            <TableColumn<()> index={()} label="Name"/>
        </TreeTableHeader<()>>
    };

    html!(
        <TreeTable<(), ProductTreeWrapper>
            mode={TreeTableMode::Compact}
            {header}
            {model}
        />
    )
}
