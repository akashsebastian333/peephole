//go:build windows

package main

import "os/exec"

func detach(cmd *exec.Cmd) {}
