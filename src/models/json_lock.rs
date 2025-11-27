use std::collections::HashMap;

use regex::Regex;
use serde::{Deserialize, Deserializer};

#[derive(Debug, Deserialize)]
pub struct JsonLockPackages {
    #[serde(deserialize_with = "clean_version_name")]
    pub packages: HashMap<String, PackageInfo>,
}

#[derive(Debug, Deserialize)]
pub struct PackageInfo {
    #[serde(deserialize_with = "to_vec")]
    pub version: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct PackageVulnerableRecord {
    #[serde(rename(deserialize = "Package"))]
    pub package: String,
    #[serde(rename(deserialize = "Version"), deserialize_with = "split_versions")]
    pub version: Vec<String>,
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

fn clean_version_name<'a, D>(deserializer: D) -> Result<HashMap<String, PackageInfo>, D::Error>
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
            corrected_map
                .get_mut(&clean_key)
                .unwrap()
                .version
                .push(value.version.pop().unwrap());
            continue;
        }
        corrected_map.insert(clean_key, value);
    }

    Ok(corrected_map)
}

fn to_vec<'a, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'a>,
{
    let s = String::deserialize(deserializer).expect("Failed to deserialize version string");

    Ok(vec![s])
}
