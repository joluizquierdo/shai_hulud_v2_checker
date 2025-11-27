use std::{fs, path::Path, process};
const JSON_LOCK_FILE: &str = "package-lock.json";

fn main() {
    //TODO: read JSON from CLI arg or default to JSON_LOCK_FILE
    let path = Path::new(JSON_LOCK_FILE);
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

    // let json_str = fs::read_to_string();
}
