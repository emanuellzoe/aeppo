package main

import "os/exec"

func run(cmd string) {
	shell, flag := "sh", "-c"
	_ = exec.Command(shell, flag, cmd).Run()
}
