/// Try cleaning up the file extension of a JSON file.
pub fn clean_ext(name: &str) -> String {
    let mut name = match name.strip_suffix(".bz2") {
        Some(name) => name.to_string(),
        None => name.to_string(),
    };

    if !name.ends_with(".json") {
        name.push_str(".json");
    }

    name
}
