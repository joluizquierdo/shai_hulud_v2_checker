mod models;

use async_lock::Mutex;
use chrono::{DateTime, Utc};
use models::json_lock::{JsonLockPackages, PackageView, PackageVulnerableRecord};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    process::{self, Command},
    sync::Arc,
};

const JSON_LOCK_FILE: &str = "examples/package-lock.json";
const AFFECTED_PACKAGES_URL: &str = "https://github.com/wiz-sec-public/wiz-research-iocs/raw/refs/heads/main/reports/shai-hulud-2-packages.csv";
const ATTACK_DATE: &str = "2025-11-24T03:16:26.000Z";

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

async fn check_possible_vulnerable_packages(packages: &mut JsonLockPackages) -> JsonLockPackages {
    let attack_datetime: DateTime<Utc> = ATTACK_DATE.parse().expect("Failed to parse attack date");
    let possibly_vulnerable = Arc::new(Mutex::new(JsonLockPackages::new()));
    let packages_arc = Arc::new(Mutex::new(HashMap::new()));

    // Move packages out to avoid borrow issues
    let mut temp_packages = HashMap::new();
    std::mem::swap(&mut packages.packages, &mut temp_packages);
    *packages_arc.lock().await = temp_packages;

    let package_keys: Vec<String> = packages_arc.lock().await.keys().cloned().collect();

    // Create a semaphore to limit concurrent tasks to 10
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

fn check_vulnerable_packages(
    vulnerabilities: &HashMap<String, Vec<String>>,
    packages: &mut JsonLockPackages,
) -> JsonLockPackages {
    let mut vulnerable_packages = JsonLockPackages::new();
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

async fn get_npm_package_view(package_name: &str) -> Option<PackageView> {
    let output = smol::process::Command::new("npm")
        .arg("view")
        .arg(package_name)
        .arg("--json")
        .output()
        .await
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let info = String::from_utf8_lossy(&output.stdout).trim().to_string();
    serde_json::from_str(&info).ok()
}
