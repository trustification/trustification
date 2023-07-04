use csaf::definitions::ProductIdT;
use csaf::product_tree::Relationship;
use csaf::Csaf;

pub fn trace_product(csaf: &Csaf, product: &ProductIdT) {
    for rela in find_product_relations(csaf, product) {}
}

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
