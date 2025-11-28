use crate::models::package::PackageView;
use std::process::Command;

pub async fn get_npm_package_view(package_name: &str) -> Option<PackageView> {
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

pub fn is_npm_installed() -> bool {
    Command::new("npm").arg("--version").output().is_ok()
}
