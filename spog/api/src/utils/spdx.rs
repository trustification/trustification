use spdx_rs::models::SPDX;

/// find all PURLs in the package information
///
/// This walks through all package information entries, returning a tuple of (purl, id).
#[allow(unused)]
pub fn find_purls(spdx: &SPDX) -> impl Iterator<Item = (&str, &str)> {
    spdx.package_information.iter().flat_map(|pi| {
        pi.external_reference
            .iter()
            .filter_map(|er| match er.reference_type == "purl" {
                true => Some((er.reference_locator.as_str(), pi.package_spdx_identifier.as_str())),
                false => None,
            })
    })
}
