//! NPM CLI integration utilities.
//!
//! This module provides functions to interact with the NPM command-line tool,
//! including checking for NPM installation and retrieving package metadata.

use crate::models::package::PackageView;
use std::process::Command;

/// Retrieves detailed metadata for an NPM package using `npm view`.
///
/// This function executes `npm view <package_name> --json` asynchronously to fetch
/// package information including publication times for all versions.
///
/// # Arguments
/// * `package_name` - The name of the NPM package to query
///
/// # Returns
/// * `Some(PackageView)` - If the package exists and data was successfully retrieved
/// * `None` - If the package name is empty, the command fails, or JSON parsing fails
///
/// # Examples
/// ```no_run
/// use shai_hulud_v2_checker::npm::get_npm_package_view;
///
/// # async fn example() {
/// if let Some(view) = get_npm_package_view("express").await {
///     println!("Package metadata: {:?}", view);
/// }
/// # }
/// ```
pub async fn get_npm_package_view(package_name: &str) -> Option<PackageView> {
    if package_name.is_empty() {
        return None;
    }

    let output = smol::process::Command::new("npm")
        .arg("view")
        .arg(package_name)
        .arg("--json")
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let info = String::from_utf8_lossy(&output.stdout).trim().to_string();
    serde_json::from_str(&info).ok()
}

/// Checks whether NPM is installed and available in the system PATH.
///
/// This function attempts to execute `npm --version` to verify NPM availability.
///
/// # Returns
/// * `true` - If NPM is installed and the command executes successfully
/// * `false` - If NPM is not found or the command fails
///
/// # Examples
/// ```no_run
/// use shai_hulud_v2_checker::npm::is_npm_installed;
///
/// if !is_npm_installed() {
///     eprintln!("NPM is required but not installed");
/// }
/// ```
pub fn is_npm_installed() -> bool {
    Command::new("npm").arg("--version").output().is_ok()
}
