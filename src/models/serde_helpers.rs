//! Custom serde deserializers for complex data transformations.
//!
//! This module provides specialized deserializers that transform data during
//! JSON/CSV parsing to create clean, normalized data structures.

use super::package::PackageInfo;
use regex::Regex;
use serde::{Deserialize, Deserializer};
use std::collections::HashMap;

/// Deserializes a comma/pipe-separated version string into a vector.
///
/// This function parses version strings from the CSV format (e.g., "1.0.0||1.0.1")
/// into a vector of individual version strings (e.g., ["1.0.0", "1.0.1"]).
/// It also removes "=" prefix characters that may appear in the CSV.
///
/// # Format
/// - Versions are separated by "||"
/// - Leading "=" characters are stripped from each version
/// - Whitespace is trimmed
///
/// # Examples
/// ```text
/// Input:  "=1.0.0||=1.0.1"
/// Output: vec!["1.0.0", "1.0.1"]
/// ```
pub fn split_versions<'a, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'a>,
{
    let str = String::deserialize(deserializer).expect("Failed to deserialize versions string");
    let versions: Vec<String> = str
        .split("||")
        .map(|s| String::from(s.replace("=", "").trim()))
        .collect();

    Ok(versions)
}

/// Deserializes and cleans package names from package-lock.json node_modules paths.
///
/// This function transforms the "packages" field from package-lock.json, which uses
/// full node_modules paths as keys (e.g., "node_modules/express" or
/// "node_modules/@babel/core"), into a clean HashMap with just the package names.
///
/// # Transformation
/// - Extracts package name from paths like "node_modules/package-name"
/// - Handles scoped packages like "@scope/package-name"
/// - Merges duplicate packages with different versions
/// - Deduplicates version numbers within each package
/// - Skips empty keys
///
/// # Examples
/// ```text
/// Input key:  "node_modules/express"
/// Output key: "express"
///
/// Input key:  "node_modules/@babel/core"
/// Output key: "@babel/core"
/// ```
///
/// # Panics
/// Panics if the regex pattern fails to match a valid node_modules path.
pub fn clean_version_name<'a, D>(deserializer: D) -> Result<HashMap<String, PackageInfo>, D::Error>
where
    D: Deserializer<'a>,
{
    let mut hash_map: HashMap<String, PackageInfo> =
        HashMap::deserialize(deserializer).expect("Failed to deserialize version name string");

    let mut corrected_map: HashMap<String, PackageInfo> = HashMap::new();
    let re = Regex::new(r".*node_modules/(@{0,1}.+)$").expect("Invalid regex pattern");
    let map_keys: Vec<String> = hash_map.keys().map(|k| k.to_string()).collect();
    for k in map_keys {
        if k.is_empty() {
            continue;
        }

        let clean_key = re
            .captures(&k)
            .expect("No captures found")
            .get(1)
            .expect("No match found")
            .as_str()
            .to_string();

        let mut value = hash_map.remove(&k).expect("Failed to remove the entry");
        if corrected_map.contains_key(&clean_key) {
            let value_version = value.version.pop().unwrap();
            let corrected_versions = &corrected_map.get(&clean_key).unwrap().version;
            if corrected_versions.contains(&value_version) {
                continue;
            }

            corrected_map
                .get_mut(&clean_key)
                .unwrap()
                .version
                .push(value_version);
            continue;
        }
        corrected_map.insert(clean_key, value);
    }

    Ok(corrected_map)
}

/// Deserializes a single string value into a vector containing that string.
///
/// This helper wraps a string field into a vector, allowing the application to
/// uniformly handle package versions as vectors even when package-lock.json
/// only contains a single version string.
///
/// # Examples
/// ```text
/// Input:  "1.2.3"
/// Output: vec!["1.2.3"]
/// ```
pub fn to_vec<'a, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'a>,
{
    let s = String::deserialize(deserializer).expect("Failed to deserialize version string");

    Ok(vec![s])
}
