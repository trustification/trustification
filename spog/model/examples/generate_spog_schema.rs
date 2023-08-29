use spog_model::config::Configuration;

fn main() -> anyhow::Result<()> {
    let schema = schemars::schema_for!(Configuration);
    let path = "spog/model/schema/config.json";
    {
        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, &schema)?;
    }
    println!("Wrote schema to: {path}");

    Ok(())
}
