use std::collections::HashMap;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct JsonLockPackages {
    pub packages: HashMap<String, PackageInfo>,
}

#[derive(Debug, Deserialize)]
pub struct PackageInfo {
    pub version: String,
}
