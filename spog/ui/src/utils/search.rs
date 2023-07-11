/// Create an `OR` group from a list of terms. In case the iterator is empty, return an empty string.
pub fn or_group(terms: impl IntoIterator<Item = String>) -> impl Iterator<Item = String> {
    let mut terms = terms.into_iter();

    let first = terms.next();
    let (prefix, suffix) = match &first {
        Some(_) => (Some("(".to_string()), Some(")".to_string())),
        None => (None, None),
    };

    prefix
        .into_iter()
        .chain(itertools::intersperse(first.into_iter().chain(terms), "OR".to_string()))
        .chain(suffix)
}

#[cfg(test)]
mod test {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn empty() {
        let s = or_group(vec![]).join(" ");
        assert_eq!(s, "");
    }

    #[test]
    fn one() {
        let s = or_group(vec!["a".to_string()]).join(" ");
        assert_eq!(s, "( a )");
    }

    #[test]
    fn three() {
        let s = or_group(vec!["a".to_string(), "b".to_string(), "c".to_string()]).join(" ");
        assert_eq!(s, "( a OR b OR c )");
    }
}
