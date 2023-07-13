/// Create an `OR` group from a list of terms. In case the iterator is empty, return an empty string.
pub fn or_group<S>(terms: impl IntoIterator<Item = S>) -> impl Iterator<Item = String>
where
    S: Into<String>,
{
    let mut terms = terms.into_iter().map(|s| s.into());

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

pub trait ToFilterExpression {
    fn to_filter_expression(&self) -> String;
}

pub trait SimpleProperties {
    fn terms(&self) -> &[String];
    fn terms_mut(&mut self) -> &mut Vec<String>;
}

/// ensure that all terms are either plain or wrapped in quotes.
///
/// TODO: be able to actually escape `"` too.
pub fn escape_terms(i: impl IntoIterator<Item = String>) -> impl Iterator<Item = String> {
    i.into_iter().map(|s: String| {
        if s.chars().any(|c| !c.is_alphanumeric()) {
            format!(r#""{}""#, s.replace('"', ""))
        } else {
            s
        }
    })
}

#[cfg(test)]
mod test {
    use super::*;
    use itertools::Itertools;

    #[test]
    fn empty() {
        let s = or_group(Vec::<String>::new()).join(" ");
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
