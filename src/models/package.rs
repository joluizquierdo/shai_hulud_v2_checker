//! Data models for NPM packages and vulnerability records.
//!
//! This module defines the core data structures used throughout the application
//! for representing package information, vulnerability data, and NPM metadata.

use super::serde_helpers::{clean_version_name, split_versions, to_vec};
use serde::Deserialize;
use std::collections::HashMap;

/// Represents metadata retrieved from `npm view` for a specific package.
///
/// This structure contains publication time information for all versions of a package,
/// which is used to determine if versions were published after the attack date.
#[derive(Debug, Deserialize)]
pub struct PackageView {
    /// Map of version numbers to their publication timestamps (ISO 8601 format)
    pub time: HashMap<String, String>,
}

/// Represents the complete set of packages from a package-lock.json file.
///
/// This structure is deserialized from package-lock.json with custom processing
/// to extract clean package names and normalize the data structure.
#[derive(Debug, Deserialize)]
pub struct NpmLockPackages {
    /// Map of package names to their installation information
    ///
    /// The keys are clean package names (e.g., "express" or "@babel/core")
    /// extracted from the full node_modules paths in package-lock.json
    #[serde(deserialize_with = "clean_version_name")]
    pub packages: HashMap<String, PackageInfo>,
}

impl NpmLockPackages {
    /// Creates a new empty `NpmLockPackages` instance.
    ///
    /// # Examples
    /// ```
    /// use shai_hulud_v2_checker::models::package::NpmLockPackages;
    ///
    /// let packages = NpmLockPackages::new();
    /// assert_eq!(packages.packages.len(), 0);
    /// ```
    pub fn new() -> Self {
        NpmLockPackages {
            packages: HashMap::new(),
        }
    }
}

/// Information about an installed package.
///
/// This structure represents a single package entry from package-lock.json,
/// including its installed version(s) and scan status.
#[derive(Debug, Deserialize, Default, Clone)]
pub struct PackageInfo {
    /// List of installed version numbers for this package
    ///
    /// Multiple versions can exist if the package appears at different
    /// locations in the dependency tree
    #[serde(deserialize_with = "to_vec")]
    pub version: Vec<String>,

    /// Whether this package was skipped during vulnerability scanning
    ///
    /// Set to true if NPM metadata could not be retrieved for this package
    #[serde(default)]
    pub skipped_scan: bool,
}

/// A record from the CSV file of known vulnerable packages.
///
/// This structure represents a single row in the Shai Hulud V2 vulnerability
/// CSV, containing a package name and its affected versions.
#[derive(Debug, Deserialize)]
pub struct PackageVulnerableRecord {
    /// The name of the vulnerable package
    #[serde(rename(deserialize = "Package"))]
    pub package: String,

    /// List of version numbers known to be vulnerable
    ///
    /// Versions are split from CSV format (e.g., "1.0.0||1.0.1" becomes ["1.0.0", "1.0.1"])
    #[serde(rename(deserialize = "Version"), deserialize_with = "split_versions")]
    pub version: Vec<String>,
}
