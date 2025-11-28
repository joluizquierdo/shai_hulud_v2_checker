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

/// Main entry point for the Shai Hulud V2 vulnerability checker.
///
/// This function orchestrates the vulnerability scanning process:
/// 1. Parses CLI arguments
/// 2. Verifies NPM is installed
/// 3. Determines which package-lock.json file to scan
/// 4. Parses the package-lock.json file
/// 5. Downloads the list of known affected packages
/// 6. Checks for known vulnerabilities
/// 7. Checks for possible vulnerabilities based on publish dates
/// 8. Reports all findings to the user
fn main() {
    let args = Args::parse();

    if !is_npm_installed() {
        eprintln!("NPM is not installed or not found in PATH. Please install NPM to proceed.");
        process::exit(1);
    }

    // Resolve lock file path from CLI arguments or auto-discovery
    let lock_file_path = resolve_lock_file_path(&args);
    let npm_packages = parse_npm_json(&lock_file_path);

    println!(
        "🔧 Using {} concurrent threads for npm view commands",
        args.threads_num
    );
    println!(
        "🔄 Packages lock Json processed succesfully!\n\t🔎 Found {} installed packages",
        npm_packages.packages.len()
    );

    let affected_packages = download_list_of_affected_packages();

    println!(
        "⏬ List of affected packages Downloaded! \n\t🔎 Found {} vulnerable 🦠 packages",
        affected_packages.len()
    );

    // First check: known vulnerabilities
    let (npm_packages, vulnerable_packages) =
        check_vulnerable_packages(&affected_packages, npm_packages);

    // Second check: possible vulnerabilities based on publish date
    let (_remaining_packages, possibly_vulnerable_packages) = smol::block_on(
        check_possible_vulnerable_packages(npm_packages, args.threads_num),
    );

    let vulnerable_packages_count = vulnerable_packages.packages.len();
    let possibly_vulnerable_packages_count = possibly_vulnerable_packages.packages.len();
    let skipped_packages: Vec<_> = possibly_vulnerable_packages
        .packages
        .iter()
        .filter(|(_, v)| v.skipped_scan)
        .collect();
    let skipped_packages_count = skipped_packages.len();

    println!("\n🔚 Scan completed!");
    if vulnerable_packages_count == 0 {
        println!("✅ No vulnerable packages found!");
    } else {
        println!(
            "❗ Total vulnerable packages found: {}",
            vulnerable_packages_count
        );

        for vuln_package in vulnerable_packages.packages.keys() {
            println!("\t- {}", vuln_package);
        }
    }

    if possibly_vulnerable_packages_count == 0 {
        println!("✅ No possibly vulnerable packages found!");
    } else {
        println!(
            "⚠️  Total possibly vulnerable packages found: {}",
            possibly_vulnerable_packages_count
        );

        for possible_vuln_package in possibly_vulnerable_packages.packages.keys() {
            println!("\t- {}", possible_vuln_package);
        }
    }

    if skipped_packages_count > 0 {
        println!(
            "⚠️  Total packages skipped during possible vulnerability check: {}",
            skipped_packages_count
        );

        for (skipped_package_name, _) in skipped_packages {
            println!("\t- {}", skipped_package_name);
        }
    }
}
