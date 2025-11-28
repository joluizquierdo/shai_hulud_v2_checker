//! Vulnerability scanning logic.
//!
//! This module implements two types of vulnerability checks:
//! 1. Known vulnerabilities - matching against a curated list of affected packages
//! 2. Possible vulnerabilities - checking if packages were published after the attack date

use crate::models::package::NpmLockPackages;
use crate::npm::get_npm_package_view;
use async_lock::Mutex;
use chrono::{DateTime, Utc};
use std::{collections::HashMap, sync::Arc};

/// The timestamp when the Shai Hulud V2 attack was detected
const ATTACK_DATE: &str = "2025-11-24T03:16:26.000Z";

/// Checks packages for possible vulnerabilities based on publication date.
///
/// This function performs concurrent scans of all installed packages, checking if any
/// versions were published after the Shai Hulud V2 attack date. Packages published
/// after this date are flagged as potentially vulnerable and require manual review.
///
/// The function uses async concurrency with a semaphore limiting to 5 concurrent
/// tasks to avoid overwhelming the NPM registry or the local system.
///
/// # Arguments
/// * `packages` - The complete list of installed packages to scan
///
/// # Returns
/// A tuple containing:
/// * `NpmLockPackages` - Packages that were not flagged as possibly vulnerable
/// * `NpmLockPackages` - Packages that may be vulnerable (published after attack date)
///
/// # Behavior
/// - Packages that cannot be queried via NPM are marked with `skipped_scan = true`
/// - For each package, all installed versions are checked against their publish dates
/// - If any version was published after the attack date, the entire package is flagged
/// - Progress is printed to stdout for each package checked
///
/// # Examples
/// ```no_run
/// use shai_hulud_v2_checker::scanner::check_possible_vulnerable_packages;
/// use shai_hulud_v2_checker::models::package::NpmLockPackages;
///
/// # async fn example(packages: NpmLockPackages) {
/// let (safe, vulnerable) = check_possible_vulnerable_packages(packages).await;
/// println!("Possibly vulnerable: {}", vulnerable.packages.len());
/// # }
/// ```
pub async fn check_possible_vulnerable_packages(
    packages: NpmLockPackages,
) -> (NpmLockPackages, NpmLockPackages) {
    let attack_datetime: DateTime<Utc> = ATTACK_DATE.parse().expect("Failed to parse attack date");
    let possibly_vulnerable = Arc::new(Mutex::new(NpmLockPackages::new()));
    let packages_arc = Arc::new(Mutex::new(packages.packages));

    let package_keys: Vec<String> = packages_arc.lock().await.keys().cloned().collect();

    // Create a semaphore to limit concurrent tasks to 5
    let semaphore = Arc::new(async_lock::Semaphore::new(5));
    let buffer_lock = Arc::new(Mutex::new(()));

    let mut tasks = Vec::new();

    for pkg_key in package_keys {
        let packages_clone = Arc::clone(&packages_arc);
        let possibly_vulnerable_clone = Arc::clone(&possibly_vulnerable);
        let semaphore_clone = Arc::clone(&semaphore);
        let buffer_lock_clone = Arc::clone(&buffer_lock);

        let task = smol::spawn(async move {
            let mut output = String::new();
            let _permit = semaphore_clone.acquire().await;

            output.push_str("\n----------------------------------------\n");
            output.push_str(&format!(
                "🔎 Checking possible vulnerable package '{}'\n",
                pkg_key
            ));

            let package_view = match get_npm_package_view(&pkg_key).await {
                Some(pv) => pv,
                None => {
                    output.push_str(&format!(
                        "\t⚠️  Could not retrieve npm view for package '{}', skipping possible vulnerability check.\n",
                        pkg_key
                    ));
                    let mut pkgs = packages_clone.lock().await;
                    if let Some(pkg_info) = pkgs.get_mut(&pkg_key) {
                        pkg_info.skipped_scan = true;
                    }

                    // Print before returning
                    let _buffer_guard = buffer_lock_clone.lock().await;
                    print!("{}", output);
                    return;
                }
            };

            output.push_str(&format!(
                "\t📦 Retrieved npm view for package '{}', checking versions...\n",
                pkg_key
            ));

            let mut maybe_vulnerable = false;

            let package_info = {
                let pkgs = packages_clone.lock().await;
                pkgs.get(&pkg_key).cloned()
            };

            if let Some(package_info) = package_info {
                for ver in package_info.version.iter() {
                    let version_created = package_view.time.get(ver);
                    let version_created = match version_created {
                        Some(vc) => vc,
                        None => {
                            output.push_str(&format!(
                                "\t⚠️  Could not find creation time for version '{}' of package '{}', skipping this version.\n",
                                ver, pkg_key
                            ));
                            continue;
                        }
                    };

                    let version_created_datetime: DateTime<Utc> = version_created
                        .parse()
                        .expect("Failed to parse version time");

                    if version_created_datetime > attack_datetime {
                        output.push_str(&format!(
                            "\t❗ Version '{}' of package '{}' was published on '{}' after the attack date ({}), it may be vulnerable.\n",
                            ver, pkg_key, version_created, ATTACK_DATE
                        ));
                        maybe_vulnerable = true;
                        break;
                    } else {
                        output.push_str(&format!(
                            "\t✅ Version '{}' of package '{}' was published on '{}' before the attack date ({}), it is not vulnerable.\n",
                            ver, pkg_key, version_created, ATTACK_DATE
                        ));
                    }
                }

                if maybe_vulnerable {
                    let mut pkgs = packages_clone.lock().await;
                    if let Some(value) = pkgs.remove(&pkg_key) {
                        let mut vuln_pkgs = possibly_vulnerable_clone.lock().await;
                        vuln_pkgs.packages.insert(pkg_key.clone(), value);
                    }
                }
            }

            let _buffer_guard = buffer_lock_clone.lock().await;
            print!("{}", output);
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete
    for task in tasks {
        task.await;
    }

    // Return both remaining packages and vulnerable packages
    let remaining_packages = NpmLockPackages {
        packages: Arc::try_unwrap(packages_arc).unwrap().into_inner(),
    };
    let vulnerable_packages = Arc::try_unwrap(possibly_vulnerable).unwrap().into_inner();

    (remaining_packages, vulnerable_packages)
}

/// Checks installed packages against a list of known vulnerabilities.
///
/// This function compares installed packages with a curated list of packages and
/// versions known to be affected by the Shai Hulud V2 attack. It performs exact
/// matching on both package names and version numbers.
///
/// # Arguments
/// * `vulnerabilities` - HashMap of known vulnerable packages to their affected versions
/// * `packages` - The complete list of installed packages to check
///
/// # Returns
/// A tuple containing:
/// * `NpmLockPackages` - Packages that are not in the vulnerability list
/// * `NpmLockPackages` - Packages confirmed to be vulnerable
///
/// # Behavior
/// - Only packages present in both lists are flagged as vulnerable
/// - Version matching is exact (e.g., "1.2.3" must match exactly)
/// - Progress and findings are printed to stdout
/// - Vulnerable packages are removed from the input list and added to the output list
///
/// # Examples
/// ```no_run
/// use std::collections::HashMap;
/// use shai_hulud_v2_checker::scanner::check_vulnerable_packages;
/// use shai_hulud_v2_checker::models::package::NpmLockPackages;
///
/// let mut vulnerabilities = HashMap::new();
/// vulnerabilities.insert("bad-package".to_string(), vec!["1.0.0".to_string()]);
///
/// # let packages = NpmLockPackages::new();
/// let (safe, vulnerable) = check_vulnerable_packages(&vulnerabilities, packages);
/// ```
pub fn check_vulnerable_packages(
    vulnerabilities: &HashMap<String, Vec<String>>,
    mut packages: NpmLockPackages,
) -> (NpmLockPackages, NpmLockPackages) {
    let mut vulnerable_packages = NpmLockPackages::new();
    for (vuln_package, vuln_versions) in vulnerabilities.iter() {
        println!("\n----------------------------------------");
        println!("🔎 Checking package '{}'", vuln_package);
        if let Some(installed_package) = packages.packages.get(vuln_package) {
            println!("⚠️  Vulnerable package found: '{}'", vuln_package);
            for installed_version in installed_package.version.iter() {
                println!("\t🔍 Installed version found: '{}'", installed_version);
                if vuln_versions.iter().any(|v| v == installed_version) {
                    println!(
                        "\t❗ Version '{}' of package '{}' is VULNERABLE!",
                        installed_version, vuln_package
                    );
                }
            }

            let vulnerable_package = packages
                .packages
                .remove(vuln_package)
                .expect("Package should exist");
            vulnerable_packages
                .packages
                .insert(vuln_package.clone(), vulnerable_package);
        } else {
            println!(
                "✅ Package '{}' not found among installed packages",
                vuln_package
            );
        }
    }

    (packages, vulnerable_packages)
}
