use std::path::PathBuf;

fn main() -> anyhow::Result<()> {
    let output = std::env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("openapi/redactor-http.yaml"));
    let yaml = serde_yaml::to_string(&redactor_http::openapi())?;
    std::fs::write(&output, yaml)?;
    Ok(())
}
