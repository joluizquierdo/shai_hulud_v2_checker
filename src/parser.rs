//! JSON parsing utilities for package-lock.json files.
//!
//! This module handles reading and parsing NPM package-lock.json files into
//! structured data types for vulnerability analysis.

use crate::models::package::NpmLockPackages;
use std::{fs, path::Path, process};

/// Parses an NPM package-lock.json file into a structured format.
///
/// This function reads a package-lock.json file from disk and deserializes it into
/// the `NpmLockPackages` structure, which contains information about all installed
/// packages and their versions.
///
/// # Arguments
/// * `path` - The filesystem path to the package-lock.json file
///
/// # Returns
/// An `NpmLockPackages` struct containing all parsed package information
///
/// # Panics
/// This function will exit the process (via `process::exit(1)`) if:
/// - The file doesn't exist
/// - The path is not a valid file
/// - The file cannot be read
/// - The JSON cannot be parsed
///
/// # Examples
/// ```no_run
/// use std::path::Path;
/// use shai_hulud_v2_checker::parser::parse_npm_json;
///
/// let path = Path::new("package-lock.json");
/// let packages = parse_npm_json(path);
/// println!("Found {} packages", packages.packages.len());
/// ```
pub fn parse_npm_json(path: &Path) -> NpmLockPackages {
    if !path.exists() || !path.is_file() {
        eprintln!(
            "File '{}' doesn't exists or is not a valid file aborting",
            path.to_string_lossy()
        );
        process::exit(1);
    }
    println!(
        "File '{}' found, proceeding with the scan...",
        path.to_string_lossy()
    );

    let json_lock_content = fs::read_to_string(path).expect("Failed to read json lock file");
    serde_json::from_str(&json_lock_content).expect("Failed to parse JSON")
}
