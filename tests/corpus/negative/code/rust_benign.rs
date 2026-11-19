use std::process::Command;

fn main() {
    // Command::new("sh").arg("-c").arg(user) in a comment
    let _ = Command::new("git").args(["rev-parse", "HEAD"]).output();
    let _ = Command::new(program).arg(path).status();
    let label: &'static str = "Command::new(\"sh\")";
    let _ = Command::new("sh").arg("-c").arg("echo hi").status();
}
