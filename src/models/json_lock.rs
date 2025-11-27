use std::collections::HashMap;

use serde::{Deserialize, Deserializer};

#[derive(Debug, Deserialize)]
pub struct JsonLockPackages {
    pub packages: HashMap<String, PackageInfo>,
}

#[derive(Debug, Deserialize)]
pub struct PackageInfo {
    pub version: String,
}

#[derive(Debug, Deserialize)]
pub struct PackageVulnerableRecord {
    #[serde(rename(deserialize = "Package"))]
    pub package: String,
    #[serde(rename(deserialize = "Version"), deserialize_with = "split_versions")]
    pub vesion: Vec<String>,
}

fn split_versions<'a, D>(deserializer: D) -> Result<Vec<String>, D::Error>
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
