package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type debtMarker struct {
	File string
	Line int
	Text string
}

var skipDirs = map[string]bool{
	".git": true, "node_modules": true, ".peephole": true, "vendor": true,
	"dist": true, "build": true, "__pycache__": true, ".venv": true,
}

func harvestSecDebt(root string) []debtMarker {
	var out []debtMarker
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		if fi, e := d.Info(); e != nil || fi.Size() > 1<<20 {
			return nil
		}
		f, e := os.Open(path)
		if e != nil {
			return nil
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		n := 0
		for sc.Scan() {
			n++
			line := sc.Text()
			if reSecDebt.MatchString(line) {
				rel, _ := filepath.Rel(root, path)
				out = append(out, debtMarker{File: rel, Line: n, Text: strings.TrimSpace(line)})
				if len(out) >= 500 {
					return filepath.SkipAll
				}
			}
		}
		return nil
	})
	return out
}

func loadApprovals(sd string) []string {
	b, err := os.ReadFile(filepath.Join(sd, "secdebt-approved"))
	if err != nil {
		return nil
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" && !strings.HasPrefix(ln, "#") {
			out = append(out, ln)
		}
	}
	return out
}

func isApproved(m debtMarker, approvals []string) bool {
	key := m.File + ":" + strconv.Itoa(m.Line)
	for _, a := range approvals {
		if a == m.File || a == key {
			return true
		}
	}
	return false
}
