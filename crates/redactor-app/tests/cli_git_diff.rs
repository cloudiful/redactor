use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn write_fixture(name: &str, content: &str) -> PathBuf {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("redactor-{name}-{stamp}.txt"));
    fs::write(&path, content).expect("write fixture");
    path
}

#[test]
fn detect_git_diff_skips_file_headers() {
    let input = write_fixture(
        "detect-git-diff",
        concat!(
            "diff --git a/config.yml b/config.yml\n",
            "index 1111111..2222222 100644\n",
            "--- a/config.yml\n",
            "+++ b/config.yml\n",
            "@@ -1,1 +1,1 @@\n",
            "+host=prod.internal.example.com\n",
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_redactor"))
        .args([
            "detect",
            "--input-kind",
            "git-diff",
            "--redact-domain",
            "true",
            "--report",
            "json",
            input.to_str().expect("input path"),
        ])
        .output()
        .expect("run detect");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("prod.internal.example.com"));
    assert!(!stdout.contains("config.yml"));
    let _ = fs::remove_file(input);
}

#[test]
fn redact_git_diff_preserves_patch_shape_and_reports_stats() {
    let input = write_fixture(
        "redact-git-diff",
        concat!(
            "diff --git a/.env b/.env\n",
            "index 1111111..2222222 100644\n",
            "--- a/.env\n",
            "+++ b/.env\n",
            "@@ -1,1 +1,1 @@\n",
            "+API_TOKEN=sk_live_1234567890ABCDEFghij\n",
        ),
    );

    let output = Command::new(env!("CARGO_BIN_EXE_redactor"))
        .args([
            "redact",
            "--input-kind",
            "git-diff",
            "--report",
            "json",
            input.to_str().expect("input path"),
        ])
        .output()
        .expect("run redact");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout");
    assert!(stdout.contains("\"redacted_text\""));
    assert!(stdout.contains("diff --git a/.env b/.env"));
    assert!(stdout.contains("+API_TOKEN=__R_SECRET_001__"));
    assert!(stdout.contains("\"stats\""));
    assert!(stdout.contains("\"llm_configured\": false"));
    let _ = fs::remove_file(input);
}
