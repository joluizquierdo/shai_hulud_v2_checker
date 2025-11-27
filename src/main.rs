mod models;

use models::json_lock::JsonLockPackages;
use std::{fs, path::Path, process};

const JSON_LOCK_FILE: &str = "examples/package-lock.json";

fn main() {
    //TODO: read JSON from CLI arg or default to JSON_LOCK_FILE
    let path = Path::new(JSON_LOCK_FILE);
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
    let npm_packages: JsonLockPackages =
        serde_json::from_str(&json_lock_content).expect("Failed to parse JSON");

    println!(
        "Packages lock Json processed succesfully! Found {} packages",
        npm_packages.packages.len()
    );

    // println!("Parsed NPM Packages: {:#?}", npm_packages);
}
