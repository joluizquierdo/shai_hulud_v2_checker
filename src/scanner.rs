use crate::models::package::NpmLockPackages;
use crate::npm::get_npm_package_view;
use async_lock::Mutex;
use chrono::{DateTime, Utc};
use std::{collections::HashMap, sync::Arc};

const ATTACK_DATE: &str = "2025-11-24T03:16:26.000Z";

pub async fn check_possible_vulnerable_packages(
    packages: &mut NpmLockPackages,
) -> NpmLockPackages {
    let attack_datetime: DateTime<Utc> = ATTACK_DATE.parse().expect("Failed to parse attack date");
    let possibly_vulnerable = Arc::new(Mutex::new(NpmLockPackages::new()));
    let packages_arc = Arc::new(Mutex::new(HashMap::new()));

    // Move packages out to avoid borrow issues
    let mut temp_packages = HashMap::new();
    std::mem::swap(&mut packages.packages, &mut temp_packages);
    *packages_arc.lock().await = temp_packages;

    let package_keys: Vec<String> = packages_arc.lock().await.keys().cloned().collect();

    // Create a semaphore to limit concurrent tasks to 5
    let semaphore = Arc::new(async_lock::Semaphore::new(5));

    let mut tasks = Vec::new();

    for k in package_keys {
        let packages_clone = Arc::clone(&packages_arc);
        let possibly_vulnerable_clone = Arc::clone(&possibly_vulnerable);
        let semaphore_clone = Arc::clone(&semaphore);
        let package_name = k.clone();

        let task = smol::spawn(async move {
            let _permit = semaphore_clone.acquire().await;

            println!("\n----------------------------------------");
            println!("🔎 Checking possible vulnerable package '{}'", package_name);

            let package_view = match get_npm_package_view(&package_name).await {
                Some(pv) => pv,
                None => {
                    println!(
                        "\t⚠️  Could not retrieve npm view for package '{}', skipping possible vulnerability check.",
                        package_name
                    );
                    let mut pkgs = packages_clone.lock().await;
                    if let Some(pkg_info) = pkgs.get_mut(&package_name) {
                        pkg_info.skipped_scan = true;
                    }
                    return;
                }
            };

            let mut maybe_vulnerable = false;

            let package_info = {
                let pkgs = packages_clone.lock().await;
                pkgs.get(&package_name).cloned()
            };

            if let Some(package_info) = package_info {
                for ver in package_info.version.iter() {
                    let version_created = package_view.time.get(ver);
                    let version_created = match version_created {
                        Some(vc) => vc,
                        None => {
                            println!(
                                "\t⚠️  Could not find creation time for version '{}' of package '{}', skipping this version.",
                                ver, package_name
                            );
                            continue;
                        }
                    };

                    let version_created_datetime: DateTime<Utc> = version_created
                        .parse()
                        .expect("Failed to parse version time");

                    if version_created_datetime > attack_datetime {
                        println!(
                            "\t❗ Version '{}' of package '{}' was published on '{}' after the attack date ({}), it may be vulnerable.",
                            ver, package_name, version_created, ATTACK_DATE
                        );
                        maybe_vulnerable = true;
                        break;
                    } else {
                        println!(
                            "\t✅ Version '{}' of package '{}' was published on '{}' before the attack date ({}), it is not vulnerable.",
                            ver, package_name, version_created, ATTACK_DATE
                        );
                    }
                }

                if maybe_vulnerable {
                    let mut pkgs = packages_clone.lock().await;
                    if let Some(value) = pkgs.remove(&package_name) {
                        let mut vuln_pkgs = possibly_vulnerable_clone.lock().await;
                        vuln_pkgs.packages.insert(package_name.clone(), value);
                    }
                }
            }
        });

        tasks.push(task);
    }

    // Wait for all tasks to complete
    for task in tasks {
        task.await;
    }

    // Restore packages (minus the vulnerable ones)
    packages.packages = Arc::try_unwrap(packages_arc).unwrap().into_inner();

    Arc::try_unwrap(possibly_vulnerable).unwrap().into_inner()
}

pub fn check_vulnerable_packages(
    vulnerabilities: &HashMap<String, Vec<String>>,
    packages: &mut NpmLockPackages,
) -> NpmLockPackages {
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

    vulnerable_packages
}
