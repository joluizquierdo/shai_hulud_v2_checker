mod models;

use models::json_lock::{JsonLockPackages, PackageVulnerableRecord};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    process::{self, Command},
};

const JSON_LOCK_FILE: &str = "examples/package-lock.json";
const AFFECTED_PACKAGES_URL: &str = "https://github.com/wiz-sec-public/wiz-research-iocs/raw/refs/heads/main/reports/shai-hulud-2-packages.csv";

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

    let affected_packages = download_list_of_affected_packages();

    println!(
        "Downloaded list of affected packages succesfully! Found {} vulnerable packages",
        affected_packages.len()
    );
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

fn download_list_of_affected_packages() -> HashMap<String, Vec<String>> {
    let url = AFFECTED_PACKAGES_URL;
    let mut response = match ureq::get(url).call() {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "Failed to download from url '{}' the list of affected packages. Detailed error: \n{}",
                url, e
            );
            process::exit(1);
        }
    };
    let response_status = response.status().as_u16();
    let response_body = response.body_mut();

    if response_status != 200 {
        let error_text = response_body.read_to_string().unwrap_or(String::from(
            "Couldn't transform http content to text sorry...",
        ));
        eprintln!(
            "Failed to download from url '{}' the list of affected packages. HTTP Status: {}, HTTP content {}",
            url,
            response.status(),
            error_text
        );
        process::exit(1);
    }

    let response_text = match response_body.read_to_string() {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "Failed to decode response text from url '{}' . Detailed error: \n{}",
                url, e
            );
            process::exit(1);
        }
    };

    let mut csv_reader = csv::ReaderBuilder::new().from_reader(response_text.as_bytes());
    csv_reader
        .deserialize()
        .collect::<Result<Vec<PackageVulnerableRecord>, _>>()
        .expect("Can't parse csv file!")
        .into_iter()
        .map(|r| (r.package, r.version))
        .collect()
}
