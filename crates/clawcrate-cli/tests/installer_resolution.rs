//! Guards on how the installer and the README pick a version.
//!
//! Every ClawCrate release so far carries a SemVer prerelease identifier — the
//! hyphen in `v0.3.0-alpha.0`. GitHub's "latest release" excludes those, so
//! anything resolving through it serves whatever shipped before the alphas
//! began. That is not an edge case for this project, it is every case, and it
//! silently served a four-month-old binary from a README nobody suspected.
//!
//! These are string assertions over the script and the README rather than live
//! resolution tests, because the failure is a URL choice rather than a runtime
//! behaviour, and a test that needs the network is a test that gets disabled.

use std::fs;
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("repo root")
        .to_path_buf()
}

fn install_script() -> String {
    fs::read_to_string(repo_root().join("scripts/install.sh")).expect("read install.sh")
}

#[test]
fn default_version_resolves_the_newest_release_including_prereleases() {
    let script = install_script();

    let resolver = script
        .split("resolve_tag()")
        .nth(1)
        .expect("install.sh should define resolve_tag");
    let latest_branch = resolver
        .split("if [ \"$VERSION\" = \"stable\" ]")
        .next()
        .expect("resolve_tag should handle the default before `stable`");

    // Comments are stripped before asserting: the explanation above this code
    // necessarily names the endpoint it warns against, and a test that reads
    // prose reports the documentation as the defect.
    let latest_branch: String = latest_branch
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .collect::<Vec<_>>()
        .join("\n");
    let latest_branch = latest_branch.as_str();

    assert!(
        latest_branch.contains("releases?per_page=1"),
        "the default must resolve through the release list, which includes \
         prereleases; got:\n{latest_branch}"
    );
    assert!(
        !latest_branch.contains("releases/latest"),
        "the default must not use GitHub's latest-release endpoint: it excludes \
         prereleases, and every release so far is one"
    );
}

#[test]
fn an_explicit_stable_channel_remains_available() {
    let script = install_script();

    assert!(
        script.contains("\"$VERSION\" = \"stable\""),
        "callers who want the newest non-prerelease should still have a way to \
         ask for it"
    );
    assert!(
        script.contains("releases/latest"),
        "the stable channel is exactly GitHub's latest-release endpoint"
    );
}

#[test]
fn the_readme_install_command_does_not_resolve_through_latest() {
    let readme = fs::read_to_string(repo_root().join("README.md")).expect("read README.md");

    let install_line = readme
        .lines()
        .find(|line| line.contains("install.sh") && line.contains("curl"))
        .expect("README should show an install command");

    assert!(
        !install_line.contains("releases/latest/download"),
        "this path serves the newest non-prerelease, so it hands over a stale \
         installer script as well as a stale binary; pin the tag instead. Got:\n\
         {install_line}"
    );
    assert!(
        install_line.contains("releases/download/v"),
        "the install command should name an exact tag; got:\n{install_line}"
    );
}
