//! Network operations for downloading vulnerability data.
//!
//! This module handles fetching the list of packages affected by the Shai Hulud V2
//! supply chain attack from the official Wiz Security research repository.

use crate::models::package::PackageVulnerableRecord;
use std::{collections::HashMap, process};

/// URL to the CSV file containing the list of packages affected by Shai Hulud V2
const AFFECTED_PACKAGES_URL: &str = "https://github.com/wiz-sec-public/wiz-research-iocs/raw/refs/heads/main/reports/shai-hulud-2-packages.csv";

/// Downloads and parses the list of packages affected by the Shai Hulud V2 attack.
///
/// This function fetches a CSV file from the Wiz Security research repository containing
/// package names and their vulnerable versions. The CSV is parsed and transformed into
/// a HashMap for efficient lookup during vulnerability scanning.
///
/// # Returns
/// A HashMap where:
/// - Keys are package names (String)
/// - Values are vectors of vulnerable version strings (`Vec<String>`)
///
/// # Panics
/// This function will exit the process (via `process::exit(1)`) if:
/// - The HTTP request fails
/// - The HTTP response status is not 200
/// - The response body cannot be decoded as text
/// - The CSV parsing fails
///
/// # Examples
/// ```no_run
/// use shai_hulud_v2_checker::network::download_list_of_affected_packages;
///
/// let affected = download_list_of_affected_packages();
/// if let Some(versions) = affected.get("some-package") {
///     println!("Vulnerable versions: {:?}", versions);
/// }
/// ```
pub fn download_list_of_affected_packages() -> HashMap<String, Vec<String>> {
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

    println!(
        "⏳ Downloading the list of affected packages from '{}' ...",
        url
    );

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
