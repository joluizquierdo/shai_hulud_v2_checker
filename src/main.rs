//! Shai Hulud V2 Vulnerability Checker
//!
//! This tool scans NPM package-lock.json files to detect packages affected by the
//! Shai Hulud V2 supply chain attack. It performs two types of checks:
//! 1. Known vulnerable packages from a curated list
//! 2. Possible vulnerabilities based on package publish dates after the attack

mod models;
mod network;
mod npm;
mod parser;
mod scanner;
mod ui;

use clap::Parser;
use network::download_list_of_affected_packages;
use npm::is_npm_installed;
use parser::parse_npm_json;
use scanner::{check_possible_vulnerable_packages, check_vulnerable_packages};
use std::process;
use ui::cli::{Args, resolve_lock_file_path};
use ui::output::{print_final_report, print_scan_summary};

/// Main entry point for the Shai Hulud V2 vulnerability checker.
///
/// This function orchestrates the vulnerability scanning process:
/// 1. Parses CLI arguments and validates environment
/// 2. Loads and parses the package-lock.json file
/// 3. Downloads the list of known affected packages
/// 4. Performs vulnerability scans (known and possible vulnerabilities)
/// 5. Reports all findings to the user
fn main() {
    // 1. Setup and validation
    let args = Args::parse();
    verify_npm_installed();

    // 2. Load data
    let lock_file_path = resolve_lock_file_path(&args);
    let npm_packages = parse_npm_json(&lock_file_path);
    let affected_packages = download_list_of_affected_packages();

    print_scan_summary(
        args.threads_num,
        npm_packages.packages.len(),
        affected_packages.len(),
    );

    // 3. Perform vulnerability scans
    let (npm_packages, vulnerable_packages) =
        check_vulnerable_packages(&affected_packages, npm_packages);

    let (_remaining_packages, possibly_vulnerable_packages) = smol::block_on(
        check_possible_vulnerable_packages(npm_packages, args.threads_num),
    );

    // 4. Report results
    print_final_report(&vulnerable_packages, &possibly_vulnerable_packages);
}

/// Verifies that NPM is installed and available in the system PATH.
///
/// # Exits
/// This function will exit the process with status code 1 if NPM is not found.
fn verify_npm_installed() {
    if !is_npm_installed() {
        eprintln!("NPM is not installed or not found in PATH. Please install NPM to proceed.");
        process::exit(1);
    }
}
