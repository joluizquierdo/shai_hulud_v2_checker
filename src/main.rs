mod models;

use models::json_lock::JsonLockPackages;
use std::{
    fs,
    path::Path,
    process::{self, Command},
};

const JSON_LOCK_FILE: &str = "examples/package-lock.json";

fn main() {
    if !is_npm_installed() {
        eprintln!("NPM is not installed or not found in PATH. Please install NPM to proceed.");
        process::exit(1);
    }

    //TODO: read JSON from CLI arg or default to JSON_LOCK_FILE
    let path = Path::new(JSON_LOCK_FILE);
    let npm_packages = parse_npm_json(path);

    println!(
        "Packages lock Json processed succesfully! Found {} packages",
        npm_packages.packages.len()
    );

    // println!("Parsed NPM Packages: {:#?}", npm_packages);
}

fn parse_npm_json(path: &Path) -> JsonLockPackages {
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

fn is_npm_installed() -> bool {
    Command::new("npm").arg("--version").output().is_ok()
}
