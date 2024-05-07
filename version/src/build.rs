pub fn generate() -> anyhow::Result<()> {
    vergen::EmitBuilder::builder()
        .all_build()
        .all_git()
        .git_describe(true, true, None)
        .emit()
}
