use crate::models::package::NpmLockPackages;
use crate::npm::get_npm_package_view;
use async_lock::Mutex;
use chrono::{DateTime, Utc};
use std::{collections::HashMap, sync::Arc};

const ATTACK_DATE: &str = "2025-11-24T03:16:26.000Z";

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
