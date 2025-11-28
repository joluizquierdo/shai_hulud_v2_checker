//! Output and reporting functions for the vulnerability scanner.
//!
//! This module handles all console output and reporting, including:
//! - Initial scan summary
//! - Vulnerable packages reports
//! - Possibly vulnerable packages reports
//! - Skipped packages reports

use crate::models::package::NpmLockPackages;

/// Prints the initial scan summary with configuration and package counts.
///
/// # Arguments
/// * `threads` - Number of concurrent threads configured for scanning
/// * `package_count` - Total number of packages found in the lock file
/// * `affected_count` - Total number of known affected packages in the vulnerability list
pub fn print_scan_summary(threads: usize, package_count: usize, affected_count: usize) {
    println!(
        "🔧 Using {} concurrent threads for npm view commands",
        threads
    );
    println!(
        "🔄 Packages lock Json processed succesfully!\n\t🔎 Found {} installed packages",
        package_count
    );
    println!(
        "⏬ List of affected packages Downloaded! \n\t🔎 Found {} vulnerable 🦠 packages",
        affected_count
    );
}

/// Prints a report of packages with known vulnerabilities.
///
/// # Arguments
/// * `vulnerable_packages` - Collection of packages confirmed to be vulnerable
pub fn print_vulnerable_packages_report(vulnerable_packages: &NpmLockPackages) {
    let count = vulnerable_packages.packages.len();

    if count == 0 {
        println!("✅ No vulnerable packages found!");
    } else {
        println!("❗ Total vulnerable packages found: {}", count);

        for package_name in vulnerable_packages.packages.keys() {
            println!("\t- {}", package_name);
        }
    }
}

/// Prints a report of packages that may be vulnerable based on publish dates.
///
/// # Arguments
/// * `possibly_vulnerable_packages` - Collection of packages potentially vulnerable
pub fn print_possibly_vulnerable_packages_report(possibly_vulnerable_packages: &NpmLockPackages) {
    let count = possibly_vulnerable_packages.packages.len();

    if count == 0 {
        println!("✅ No possibly vulnerable packages found!");
    } else {
        println!("⚠️  Total possibly vulnerable packages found: {}", count);

        for package_name in possibly_vulnerable_packages.packages.keys() {
            println!("\t- {}", package_name);
        }
    }
}

/// Prints a report of packages that were skipped during vulnerability scanning.
///
/// # Arguments
/// * `possibly_vulnerable_packages` - Collection to check for skipped packages
pub fn print_skipped_packages_report(possibly_vulnerable_packages: &NpmLockPackages) {
    let skipped_packages: Vec<_> = possibly_vulnerable_packages
        .packages
        .iter()
        .filter(|(_, package_info)| package_info.skipped_scan)
        .collect();

    let count = skipped_packages.len();

    if count > 0 {
        println!(
            "⚠️  Total packages skipped during possible vulnerability check: {}",
            count
        );

        for (package_name, _) in skipped_packages {
            println!("\t- {}", package_name);
        }
    }
}

/// Prints the complete final vulnerability report.
///
/// This orchestrates all report sections:
/// 1. Known vulnerable packages
/// 2. Possibly vulnerable packages
/// 3. Skipped packages
///
/// # Arguments
/// * `vulnerable_packages` - Collection of packages with known vulnerabilities
/// * `possibly_vulnerable_packages` - Collection of packages potentially vulnerable
pub fn print_final_report(
    vulnerable_packages: &NpmLockPackages,
    possibly_vulnerable_packages: &NpmLockPackages,
) {
    println!("\n🔚 Scan completed!");

    print_vulnerable_packages_report(vulnerable_packages);
    print_possibly_vulnerable_packages_report(possibly_vulnerable_packages);
    print_skipped_packages_report(possibly_vulnerable_packages);
}
