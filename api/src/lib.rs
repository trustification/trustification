pub mod search;

pub trait Apply<T> {
    fn apply(self, value: &T) -> Self;
}
