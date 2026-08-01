//go:build windows

package main

import "os/exec"

// detach on Windows: no Setsid; the spawned process is simply not waited on.
func detach(cmd *exec.Cmd) {}
