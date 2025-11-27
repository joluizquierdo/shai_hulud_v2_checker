mod models;

use chrono::{DateTime, Utc};
use models::json_lock::{JsonLockPackages, PackageView, PackageVulnerableRecord};
use std::{
    collections::HashMap,
    fs,
    path::Path,
    process::{self, Command},
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
    let possibly_vulnerable_packages = check_possible_vulnerable_packages(&mut npm_packages);

    let vulnerable_packages_count = vulnerable_packages.packages.len();
    let possibly_vulnerable_packages_count = possibly_vulnerable_packages.packages.len();

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
}

fn check_possible_vulnerable_packages(packages: &mut JsonLockPackages) -> JsonLockPackages {
    let attack_datetime: DateTime<Utc> = ATTACK_DATE.parse().expect("Failed to parse attack date");
    let mut possibly_vulnerable_packages = JsonLockPackages::new();
    let package_keys = packages
        .packages
        .keys()
        .map(|k| k.to_string())
        .collect::<Vec<_>>();
    for k in package_keys.iter() {
        println!("\n----------------------------------------");
        println!("🔎 Checking possible vulnerable package '{}'", k);
        let mut maybe_vulnerable = false;
        let package_info = packages.packages.get_mut(k).unwrap();
        let package_view = match get_npm_package_view(k) {
            Some(pv) => pv,
            None => {
                println!(
                    "\t⚠️  Could not retrieve npm view for package '{}', skipping possible vulnerability check.",
                    k
                );
                continue;
            }
        };

        for ver in package_info.version.iter() {
            let version_created = package_view.time.get(ver);
            let version_created = match version_created {
                Some(vc) => vc,
                None => {
                    println!(
                        "\t⚠️  Could not find creation time for version '{}' of package '{}', skipping this version.",
                        ver, k
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
                    ver, k, version_created, ATTACK_DATE
                );

                maybe_vulnerable = true;
                break;
            } else {
                println!(
                    "\t✅ Version '{}' of package '{}' was published on '{}' before the attack date ({}), it is not vulnerable.",
                    ver, k, version_created, ATTACK_DATE
                );
            }
        }

        if maybe_vulnerable {
            let value = packages.packages.remove(k).expect("Package should exist");
            possibly_vulnerable_packages
                .packages
                .insert(k.to_string(), value);
        }
    }

    possibly_vulnerable_packages
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

fn get_npm_package_view(package_name: &str) -> Option<PackageView> {
    let output = Command::new("npm")
        .arg("view")
        .arg(package_name)
        .arg("--json")
        .output()
        .expect("Failed to execute npm command");

    if !output.status.success() {
        return None;
    }

    let info = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let package_view: PackageView =
        serde_json::from_str(&info).expect("Failing parsing npm view output");

    Some(package_view)
}
