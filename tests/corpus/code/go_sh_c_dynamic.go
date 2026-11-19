package main

import (
	"fmt"
	"os/exec"
)

func run(name string) {
	cmd := fmt.Sprintf("echo hi %s", name)
	_ = exec.Command("sh", "-c", cmd).Run()
	_ = exec.CommandContext(ctx, "/bin/bash", "-c", "echo "+name).Run()
}
