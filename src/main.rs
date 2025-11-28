mod models;
mod network;
mod npm;
mod parser;
mod scanner;

use network::download_list_of_affected_packages;
use npm::is_npm_installed;
use parser::parse_npm_json;
use scanner::{check_possible_vulnerable_packages, check_vulnerable_packages};
use std::{path::Path, process};

const JSON_LOCK_FILE: &str = "examples/package-lock.json";

fn main() {
    if !is_npm_installed() {
        eprintln!("NPM is not installed or not found in PATH. Please install NPM to proceed.");
        process::exit(1);
    }

    //TODO: read JSON from CLI arg or default to JSON_LOCK_FILE
    let path = Path::new(JSON_LOCK_FILE);
    let mut npm_packages = parse_npm_json(path);

    println!(
        "🔄 Packages lock Json processed succesfully!\n\t🔎 Found {} installed packages",
        npm_packages.packages.len()
    );

    let affected_packages = download_list_of_affected_packages();

    println!(
        "⏬ List of affected packages Downloaded! \n\t🔎 Found {} vulnerable 🦠 packages",
        affected_packages.len()
    );

    let vulnerable_packages = check_vulnerable_packages(&affected_packages, &mut npm_packages);
    let possibly_vulnerable_packages =
        smol::block_on(check_possible_vulnerable_packages(&mut npm_packages));

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
