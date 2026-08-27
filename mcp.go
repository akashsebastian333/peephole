package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func cliMCP() {
	kb := loadKB()
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<24)
	out := json.NewEncoder(os.Stdout)

	reply := func(id json.RawMessage, result any) {
		if len(id) == 0 || string(id) == "null" {
			return
		}
		_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	}
	replyErr := func(id json.RawMessage, code int, msg string) {
		if len(id) == 0 {
			return
		}
		_ = out.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
	}

	for in.Scan() {
		line := strings.TrimSpace(in.Text())
		if line == "" {
			continue
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal([]byte(line), &req) != nil {
			continue
		}
		switch req.Method {
		case "initialize":
			reply(req.ID, map[string]any{
				"protocolVersion": "2024-11-05",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "peephole", "version": version},
			})
		case "ping":
			reply(req.ID, map[string]any{})
		case "tools/list":
			reply(req.ID, map[string]any{"tools": []any{scanToolSpec}})
		case "tools/call":
			var p struct {
				Name string `json:"name"`
				Args struct {
					Code     string `json:"code"`
					Filename string `json:"filename"`
				} `json:"arguments"`
			}
			_ = json.Unmarshal(req.Params, &p)
			if p.Name != "scan_code" {
				replyErr(req.ID, -32602, "unknown tool: "+p.Name)
				continue
			}
			path := p.Args.Filename
			if path == "" {
				path = "snippet.txt"
			}
			reply(req.ID, map[string]any{
				"content": []any{map[string]any{"type": "text", "text": mcpScanText(kb, path, p.Args.Code)}},
				"isError": false,
			})
		default:
			if strings.HasPrefix(req.Method, "notifications/") {
				continue
			}
			replyErr(req.ID, -32601, "method not found: "+req.Method)
		}
	}
}

var scanToolSpec = map[string]any{
	"name": "scan_code",
	"description": "Check a code snippet for security vulnerabilities (CWE rules across many languages) " +
		"BEFORE writing it to disk. Call this on any security-sensitive code you are about to write - " +
		"queries, auth, crypto, file/URL/command handling, deserialization, secrets, IaC, smart contracts. " +
		"Returns HIGH-confidence findings that should be fixed before writing, plus lower-confidence review items.",
	"inputSchema": map[string]any{
		"type": "object",
		"properties": map[string]any{
			"code":     map[string]any{"type": "string", "description": "the code to check"},
			"filename": map[string]any{"type": "string", "description": "the target filename (its extension selects the language rules)"},
		},
		"required": []string{"code"},
	},
}

func mcpScanText(kb *KB, path, code string) string {
	findings := kb.scan(path, code)
	if len(findings) == 0 {
		return "peephole: no security findings. Safe to write."
	}
	var b strings.Builder
	high := 0
	for _, f := range findings {
		if f.Confidence == "high" {
			high++
		}
	}
	if high > 0 {
		fmt.Fprintf(&b, "peephole: %d HIGH-confidence finding(s) - fix before writing:\n", high)
	} else {
		b.WriteString("peephole: review items (lower confidence):\n")
	}
	for _, f := range findings {
		fmt.Fprintf(&b, "- %s %s (%s): %s\n", f.Rule.CWE, f.Rule.Name, f.Confidence, f.Rule.AttackScenario)
		if f.Rule.Exemplar.Compliant != "" {
			fmt.Fprintf(&b, "  secure pattern: %s\n", indent(f.Rule.Exemplar.Compliant))
		}
	}
	return b.String()
}
