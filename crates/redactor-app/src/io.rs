use anyhow::{Context, Result};
use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;

pub(crate) fn read_input(input: Option<PathBuf>) -> Result<String> {
    match input {
        Some(path) if path.as_os_str() == "-" => read_stdin(),
        Some(path) => fs::read_to_string(path).context("failed to read input file"),
        None => read_stdin(),
    }
}

fn read_stdin() -> Result<String> {
    let mut buffer = String::new();
    io::stdin()
        .read_to_string(&mut buffer)
        .context("failed to read stdin")?;
    Ok(buffer)
}
