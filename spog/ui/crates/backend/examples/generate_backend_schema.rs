use spog_ui_backend::Endpoints;

fn main() -> anyhow::Result<()> {
    let schema = schemars::schema_for!(Endpoints);
    let path = "crates/backend/schema/config.json";
    {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, &schema)?;
    }
    println!("Wrote schema to: {path}");

    Ok(())
}
