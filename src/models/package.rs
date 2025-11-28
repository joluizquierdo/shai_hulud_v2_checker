use super::serde_helpers::{clean_version_name, split_versions, to_vec};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
pub struct PackageView {
    pub time: HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
pub struct NpmLockPackages {
    #[serde(deserialize_with = "clean_version_name")]
    pub packages: HashMap<String, PackageInfo>,
}

impl NpmLockPackages {
    pub fn new() -> Self {
        NpmLockPackages {
            packages: HashMap::new(),
        }
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct PackageInfo {
    #[serde(deserialize_with = "to_vec")]
    pub version: Vec<String>,

    #[serde(default)]
    pub skipped_scan: bool,
}

#[derive(Debug, Deserialize)]
pub struct PackageVulnerableRecord {
    #[serde(rename(deserialize = "Package"))]
    pub package: String,
    #[serde(rename(deserialize = "Version"), deserialize_with = "split_versions")]
    pub version: Vec<String>,
}
