package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func cliLSP() {
	kb := loadKB()
	r := bufio.NewReader(os.Stdin)
	w := bufio.NewWriter(os.Stdout)

	send := func(v any) {
		b, _ := json.Marshal(v)
		fmt.Fprintf(w, "Content-Length: %d\r\n\r\n", len(b))
		w.Write(b)
		w.Flush()
	}
	reply := func(id json.RawMessage, result any) {
		send(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
	}
	diagnose := func(uri, text string) {
		send(map[string]any{"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics",
			"params": map[string]any{"uri": uri, "diagnostics": lspDiagnostics(kb, uri, text)}})
	}

	for {
		msg, err := readLSPMessage(r)
		if err != nil {
			return
		}
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params json.RawMessage `json:"params"`
		}
		if json.Unmarshal(msg, &req) != nil {
			continue
		}
		switch req.Method {
		case "initialize":
			reply(req.ID, map[string]any{
				"capabilities": map[string]any{
					"textDocumentSync": 1,
				},
				"serverInfo": map[string]any{"name": "peephole", "version": version},
			})
		case "shutdown":
			reply(req.ID, nil)
		case "exit":
			return
		case "textDocument/didOpen":
			var p struct {
				TD struct {
					URI  string `json:"uri"`
					Text string `json:"text"`
				} `json:"textDocument"`
			}
			if json.Unmarshal(req.Params, &p) == nil {
				diagnose(p.TD.URI, p.TD.Text)
			}
		case "textDocument/didChange":
			var p struct {
				TD struct {
					URI string `json:"uri"`
				} `json:"textDocument"`
				Changes []struct {
					Text string `json:"text"`
				} `json:"contentChanges"`
			}
			if json.Unmarshal(req.Params, &p) == nil && len(p.Changes) > 0 {
				diagnose(p.TD.URI, p.Changes[len(p.Changes)-1].Text)
			}
		case "textDocument/didSave":
			var p struct {
				TD struct {
					URI string `json:"uri"`
				} `json:"textDocument"`
				Text string `json:"text"`
			}
			if json.Unmarshal(req.Params, &p) == nil && p.Text != "" {
				diagnose(p.TD.URI, p.Text)
			}
		}
	}
}

func readLSPMessage(r *bufio.Reader) ([]byte, error) {
	n := 0
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if v, ok := strings.CutPrefix(line, "Content-Length:"); ok {
			n, _ = strconv.Atoi(strings.TrimSpace(v))
		}
	}
	if n <= 0 || n > 1<<24 {
		return nil, fmt.Errorf("bad content-length")
	}
	body := make([]byte, n)
	for off := 0; off < n; {
		m, err := r.Read(body[off:])
		if err != nil {
			return nil, err
		}
		off += m
	}
	return body, nil
}

func lspDiagnostics(kb *KB, uri, text string) []any {
	path := strings.TrimPrefix(uri, "file://")
	var diags []any
	for _, f := range kb.scan(path, text) {
		sev := 2
		if f.Confidence == "high" {
			sev = 1
		}
		line := firstMatchLine(f.Rule, langOf(path), text) - 1
		if line < 0 {
			line = 0
		}
		diags = append(diags, map[string]any{
			"range": map[string]any{
				"start": map[string]int{"line": line, "character": 0},
				"end":   map[string]int{"line": line, "character": 200},
			},
			"severity": sev,
			"source":   "peephole",
			"code":     f.Rule.CWE,
			"message":  f.Rule.Name + " (" + f.Confidence + "). " + f.Rule.AttackScenario,
		})
	}
	if diags == nil {
		return []any{}
	}
	return diags
}
