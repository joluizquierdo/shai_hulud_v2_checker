//! Command-line interface module.
//!
//! This module handles all CLI argument parsing and related utilities for the
//! Shai Hulud V2 vulnerability checker.

use clap::Parser;
use std::{env, path::PathBuf, process};

/// CLI arguments for the Shai Hulud V2 vulnerability checker
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    /// Path to the package-lock.json file (relative or absolute).
    /// If not provided, searches for npm lock files in the current directory.
    #[arg(short = 'f', long = "json-lock-file")]
    pub json_lock_file: Option<String>,

    /// Number of threads to spawn for running npm view commands
    #[arg(short = 't', long = "threads-num", default_value = "5")]
    pub threads_num: usize,
}

/// Searches the current directory for npm lock files.
///
/// This function looks for common npm lock file names in the current working directory.
///
/// # Returns
/// `Some(PathBuf)` containing the path to the found lock file, or `None` if no lock file is found
///
/// # Supported lock files
/// - package-lock.json
/// - npm-shrinkwrap.json
fn find_npm_lock_file() -> Option<PathBuf> {
    let current_dir = env::current_dir().ok()?;

    let lock_file_names = ["package-lock.json", "npm-shrinkwrap.json"];

    for name in &lock_file_names {
        let lock_file_path = current_dir.join(name);
        if lock_file_path.exists() && lock_file_path.is_file() {
            return Some(lock_file_path);
        }
    }

    None
}

/// Resolves the lock file path from CLI arguments or auto-discovery.
///
/// This function determines which package-lock.json file to use based on:
/// 1. The path provided via CLI argument (if any)
/// 2. Auto-discovery in the current directory
///
/// If a path is provided but doesn't exist, the program exits with an error.
/// If no path is provided and no lock file is found, the program exits with usage instructions.
///
/// # Arguments
/// * `args` - The parsed CLI arguments
///
/// # Returns
/// `PathBuf` containing the path to the lock file to scan
///
/// # Exits
/// This function will exit the process with status code 1 if:
/// - The specified file path doesn't exist
/// - No lock file is found in the current directory when auto-discovering
pub fn resolve_lock_file_path(args: &Args) -> PathBuf {
    if let Some(ref file_path) = args.json_lock_file {
        let path = PathBuf::from(file_path);
        if !path.exists() {
            eprintln!(
                "Error: The specified lock file '{}' does not exist.",
                file_path
            );
            process::exit(1);
        }
        println!("📂 Using lock file: {}", path.display());
        path
    } else {
        match find_npm_lock_file() {
            Some(path) => {
                println!("📂 Found lock file: {}", path.display());
                path
            }
            None => {
                eprintln!("Error: No npm lock file found in the current directory.");
                eprintln!("Please specify a lock file path using -f/--json-lock-file option,");
                eprintln!(
                    "or run the command from a directory containing package-lock.json or npm-shrinkwrap.json."
                );
                process::exit(1);
            }
        }
    }
}
