use csaf::definitions::{Branch, BranchesT, ProductIdT};
use csaf::product_tree::Relationship;
use csaf::Csaf;

pub fn trace_product<'a>(csaf: &'a Csaf, product: &ProductIdT) -> Vec<&'a Branch> {
    let mut result = vec![];

    if let Some(product_tree) = &csaf.product_tree {
        // let result = &mut result;
        walk_product_branches(&product_tree.branches, |parents, branch| {
            if let Some(full_name) = &branch.product {
                if &full_name.product_id == product {
                    // trace back
                    result = parents
                        .into_iter()
                        .map(|b| *b)
                        .chain(Some(branch))
                        .collect::<Vec<&'a Branch>>()
                }
            }
        });
    }

    result
}

pub fn trace_product_branches(branches: &[Branch], product: &ProductIdT) {
    for branch in branches {
        if let Some(branches) = &branch.branches {
            trace_product_branches(&branches.0, product);
        }
    }
}

pub fn walk_product_branches<'a, F>(branches: &'a Option<BranchesT>, mut f: F)
where
    F: FnMut(&[&'a Branch], &'a Branch),
{
    let mut parents = vec![];
    walk_product_branches_ref(branches, &mut parents, &mut f)
}

fn walk_product_branches_ref<'a, F>(branches: &'a Option<BranchesT>, parents: &mut Vec<&'a Branch>, f: &mut F)
where
    F: FnMut(&[&'a Branch], &'a Branch),
{
    if let Some(branches) = &branches {
        for branch in &branches.0 {
            f(parents, branch);
            parents.push(branch);
            walk_product_branches_ref(&branch.branches, parents, f);
            parents.pop();
        }
    }
}

/// find relations to a product id
pub fn find_product_relations<'a>(
    csaf: &'a Csaf,
    product: &'a ProductIdT,
) -> impl Iterator<Item = &'a Relationship> + 'a {
    csaf.product_tree
        .iter()
        .flat_map(|pt| pt.relationships.iter())
        .flat_map(|r| r.iter())
        .filter(move |p| &p.full_product_name.product_id == product)
}
