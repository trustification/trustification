use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    trustification_version::build::generate()?;
    Ok(())
}
