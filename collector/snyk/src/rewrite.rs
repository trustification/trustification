use std::str::FromStr;

use packageurl::PackageUrl;
use regex::Regex;

pub fn rewrite_purl(mut purl: PackageUrl) -> PackageUrl {
    if purl.ty() == "rpm" && matches!(purl.namespace(), Some("redhat")) {
        purl.with_namespace("rhel");
    }

    if let Some("rhel") = purl.namespace() {
        if purl.qualifiers().get("distro").is_none() {
            if let Some(version) = purl.version() {
                if let Ok(matcher) = Regex::new("\\.el(.+)$") {
                    if let Some(found) = matcher.captures(version) {
                        if let Some(distro) = found.get(1) {
                            let mut distro = distro.as_str().to_string();
                            if distro.ends_with("_0") {
                                distro = distro[0..distro.len() - 2].to_string();
                            }
                            purl.add_qualifier("distro", distro.as_str().to_string()).ok();
                        }
                    }
                }
            }
        }
    }

    purl
}

pub fn rewrite(purl: &str) -> Result<String, packageurl::Error> {
    let purl = rewrite_purl(PackageUrl::from_str(purl)?);

    Ok(purl.to_string())
}

#[cfg(test)]
mod test {
    use crate::rewrite::rewrite;

    #[test]
    fn no_rewrite() {
        assert_eq!(
            Ok("pkg:rpm/debian/openssl".to_string()),
            rewrite("pkg:rpm/debian/openssl")
        );
    }

    #[test]
    fn rewrite_redhat_no_el_version() {
        assert_eq!(
            Ok("pkg:rpm/rhel/openssl@3.0.4".to_string()),
            rewrite("pkg:rpm/redhat/openssl@3.0.4")
        );
    }

    #[test]
    fn rewrite_redhat_with_el_version() {
        assert_eq!(
            Ok("pkg:rpm/rhel/openssl@3.0.4.el9_0?distro=9".to_string()),
            rewrite("pkg:rpm/redhat/openssl@3.0.4.el9_0")
        );
    }
}
