use anyhow::{Context, Result, anyhow};
use redactor::RestoreResult;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) fn check_patch_applies(repo_root: &Path, result: &RestoreResult) -> Result<()> {
    if !result.is_valid() {
        return Ok(());
    }

    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo_root)
        .arg("apply")
        .arg("--check")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    let mut child = command
        .spawn()
        .context("failed to start `git apply --check`")?;
    child
        .stdin
        .as_mut()
        .context("failed to open git apply stdin")?
        .write_all(result.restored_text.as_bytes())
        .context("failed to feed restored patch to git apply")?;
    let output = child
        .wait_with_output()
        .context("failed to wait for git apply")?;

    if output.status.success() {
        return Ok(());
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(anyhow!(
        "restored patch failed `git apply --check`: {}",
        stderr.trim()
    ))
}
