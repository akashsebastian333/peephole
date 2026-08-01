//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detach configures cmd to run detached from the hook's process group, so the
// spawned warmcache process survives the hook's exit.
func detach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
