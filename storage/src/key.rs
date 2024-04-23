use std::fmt::{Display, Formatter};

/// A key for a document.
#[derive(Copy, Clone)]
pub struct Key<'a>(&'a str);

impl Key<'_> {}

impl<'a> From<&'a str> for Key<'a> {
    fn from(value: &'a str) -> Self {
        Self(value)
    }
}

impl<'a> From<&'a String> for Key<'a> {
    fn from(value: &'a String) -> Self {
        value.as_str().into()
    }
}

impl Display for Key<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&urlencoding::encode(self.0))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rstest::rstest;

    #[rstest]
    #[case("foo bar", "foo%20bar")]
    #[case("foo/bar", "foo%2Fbar")]
    #[case("../bar", "..%2Fbar")]
    #[case("bar/..", "bar%2F..")]
    #[case("~/bar", "~%2Fbar")]
    #[case("foo%bar", "foo%25bar")]
    fn test_not_safe(#[case] name: &str, #[case] expected_path: &str) {
        assert_eq!(format!("{}", Key::from(name)), expected_path)
    }
}
