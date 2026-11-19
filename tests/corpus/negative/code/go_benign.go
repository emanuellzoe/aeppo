package main

import (
	"net/http"
	"os/exec"
)

// exec.Command("sh", "-c", userInput) in a comment is not code.
func version() string {
	out, _ := exec.Command("git", "rev-parse", "HEAD").Output()
	_ = exec.Command("sh", "-c", "echo hi").Run()
	msg := "exec.Command(\"sh\", \"-c\", x)"
	_, _ = http.Get("https://example.invalid")
	return string(out) + msg
}
