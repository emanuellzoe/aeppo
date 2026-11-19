use std::process::Command;

fn main() {
    // Embed the git revision; compile bundled C code.
    let rev = Command::new("git").args(["rev-parse", "HEAD"]).output().unwrap();
    println!("cargo:rustc-env=GIT_REV={}", String::from_utf8_lossy(&rev.stdout).trim());
    cc::Build::new().file("src/shim.c").compile("shim");
}
