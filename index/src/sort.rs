use sikula::mir::Direction;
use tantivy::{schema::Field, Order};

/// Create a "sort by" entry from a sikula direction
pub fn sort_by(direction: Direction, field: Field) -> (Field, Order) {
    match direction {
        Direction::Descending => (field, Order::Desc),
        Direction::Ascending => (field, Order::Asc),
    }
}
