use csaf::definitions::{Branch, BranchesT, ProductIdT};
use csaf::product_tree::{ProductTree, Relationship};
use csaf::Csaf;
use std::collections::HashSet;

/// build the chain form a product ID up to the parent
pub fn trace_product<'a>(csaf: &'a Csaf, product_id: &str) -> Vec<&'a Branch> {
    let mut result = vec![];

    if let Some(product_tree) = &csaf.product_tree {
        // let result = &mut result;
        walk_product_branches(&product_tree.branches, |parents, branch| {
            if let Some(full_name) = &branch.product {
                if full_name.product_id.0 == product_id {
                    // trace back
                    result = parents.iter().copied().chain(Some(branch)).collect::<Vec<&'a Branch>>()
                }
            }
        });
    }

    result
}

/// check if a list of IDs has the purl as the final branch element
pub fn has_purl(csaf: &Csaf, ids: &Option<Vec<ProductIdT>>, purl: &str) -> bool {
    let ids = match ids {
        Some(ids) => ids,
        None => return false,
    };

    static EMPTY: Vec<Relationship> = vec![];

    let rel = csaf
        .product_tree
        .as_ref()
        .and_then(|pt| pt.relationships.as_ref())
        .unwrap_or(&EMPTY);

    let mut has = false;
    let ids = HashSet::from_iter(ids.iter().map(|p| p.0.as_str()));

    // find the branch of the PURL
    walk_product_tree_branches(&csaf.product_tree, |parents, branch| {
        if branch_has_purl(branch, purl) {
            // this branch has the purl, check if it's product is contained in the id set
            if contains_product(rel, &ids, branch) {
                has = true;
            }
            // or if any of its parents is
            for parent in parents {
                if contains_product(rel, &ids, parent) {
                    has = true;
                }
            }
        }
    });

    has
}

/// find all product IDs related to this one
pub fn related_product_ids<'a>(rel: &'a [Relationship], id: &'a str) -> impl Iterator<Item = &'a str> + 'a {
    rel.iter()
        .filter(move |rel| rel.product_reference.0 == id)
        .map(|rel| rel.full_product_name.product_id.0.as_str())
}

pub fn product_id(branch: &Branch) -> Option<&str> {
    branch.product.as_ref().map(|p| p.product_id.0.as_str())
}

/// check if the product ID of branch is contained in the set
pub fn contains_product(rel: &[Relationship], ids: &HashSet<&str>, branch: &Branch) -> bool {
    let id = product_id(branch);
    match id {
        Some(id) => {
            // directly in the set
            if ids.contains(id) {
                return true;
            }

            // or any of its related
            let related = related_product_ids(rel, id).collect::<Vec<_>>();
            for related in related {
                if ids.contains(related) {
                    return true;
                }
            }

            false
        }
        None => false,
    }
}

/// check if the branch is identified using the provided purl
pub fn branch_has_purl(branch: &Branch, purl: &str) -> bool {
    if let Some(x) = branch
        .product
        .as_ref()
        .and_then(|p| p.product_identification_helper.as_ref())
        .and_then(|pih| pih.purl.as_ref())
    {
        x.to_string() == purl
    } else {
        false
    }
}

#[allow(clippy::needless_lifetimes)]
pub fn walk_product_tree_branches<'a, F>(product_tree: &'a Option<ProductTree>, f: F)
where
    F: FnMut(&[&'a Branch], &'a Branch),
{
    if let Some(product_tree) = &product_tree {
        walk_product_branches(&product_tree.branches, f);
    }
}

#[allow(clippy::needless_lifetimes)]
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

/// check if we have a product in our product tree
pub fn has_product(csaf: &Csaf, product_id: &str) -> bool {
    !trace_product(csaf, product_id).is_empty()
}

/// find relations to a product id
pub fn find_product_relations<'a>(csaf: &'a Csaf, product: &'a str) -> impl Iterator<Item = &'a Relationship> + 'a {
    csaf.product_tree
        .iter()
        .flat_map(|pt| pt.relationships.iter())
        .flat_map(|r| r.iter())
        .filter(move |p| p.full_product_name.product_id.0 == product)
}
