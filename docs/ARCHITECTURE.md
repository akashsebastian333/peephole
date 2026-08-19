# Peephole — architecture

Diagrams and deployment topology. For the rationale behind each design decision
see [DESIGN.md](DESIGN.md); for adversary analysis see
[THREAT_MODEL.md](THREAT_MODEL.md).

The whole system is one static Go binary, invoked once per hook event, with no
daemon, no socket, no network, and no database. Every diagram below describes
process invocations, not services.

---

## 1. The two planes

Peephole has two mechanisms, and they contribute very unequally. Measured on the
live benchmark, the guidance plane does most of the work; the gate is a backstop.

```mermaid
flowchart LR
    subgraph GUIDANCE["Guidance plane — before code exists"]
        direction TB
        G1["SessionStart<br/>9-rung security ladder"]
        G2["UserPromptSubmit<br/>classify task → inject the<br/>matching CWEs + compliant exemplars"]
    end
    subgraph GATE["Enforcement plane — after code is proposed"]
        direction TB
        E1["PreToolUse<br/>scan the payload → allow / ask / deny"]
        E2["PostToolUse<br/>retro-scan what landed, log"]
        E3["Stop<br/>cite-or-exploit self-review"]
    end
    P["Developer prompt"] --> G2
    G1 & G2 -->|"additionalContext"| M["Model writes code"]
    M --> E1 --> E2 --> E3
    E3 -->|"one forced continuation"| M

    style GUIDANCE fill:#0f3d2e,stroke:#2ea043,color:#e6edf3
    style GATE fill:#3d2f0f,stroke:#d29922,color:#e6edf3
```

The asymmetry is the point: it is cheaper and more effective to make the model
write the secure version than to catch the insecure one. The gate exists for the
residual.

## 2. Hook lifecycle

```mermaid
sequenceDiagram
    autonumber
    participant H as Agent host
    participant P as peephole (new process per event)
    participant S as .peephole/ state
    participant M as Model

    H->>P: SessionStart
    P->>S: read/migrate state, verifySelf
    P-->>M: ladder + mode banner
    Note over P,S: warmcache detaches to pre-warm<br/>the slopsquat cache (~500ms saved later)

    M->>H: user prompt
    H->>P: UserPromptSubmit
    P->>P: classify(prompt) → ranked CWEs
    P-->>M: attack scenarios + compliant exemplars

    M->>H: proposes Write / Edit / Bash / MCP
    H->>P: PreToolUse (payload on stdin)
    P->>P: prefilter → 584 patterns → taint → refinements
    P->>S: append audit entry, session sets
    alt high confidence, strict/hardened
        P-->>H: permissionDecision = deny
        H-->>M: reason + secure pattern
        M->>H: regenerates
    else guided, or medium
        P-->>H: ask (human prompt; allow under --dangerously-skip-permissions)
    else clean
        P-->>H: allow
    end

    H->>H: write lands on disk
    H->>P: PostToolUse
    P->>P: retro-scan, classify landed semantic classes
    P->>S: record hunk memo + review classes

    M->>H: finishes
    H->>P: Stop
    P->>S: read reviewed classes
    opt untouched semantic class present
        P-->>M: red-team this diff, quote the guard or fix it
    end
```

## 3. Scan pipeline

```mermaid
flowchart TD
    IN["payload<br/>Content + NewString + edits[]"] --> BOUND["truncate to 256KB<br/>maxScanBytes"]
    BOUND --> LC["one strings.ToLower<br/>shared by both prefilters"]
    LC --> PROSE{".md / .rst / .adoc?"}
    PROSE -->|yes| KEEP["keep only classes real in prose<br/>CWE-798/321/259/540; skip taint"]
    PROSE -->|no| LANG["langOf(ext) → language gate"]
    LANG --> PRE{"literal prefilter hit?"}
    PRE -->|no| SKIP["skip pattern — 0 allocs"]
    PRE -->|yes| RE["RE2 match (linear, no backtracking)"]
    RE --> REF{"reject_re / require_re / prev_not<br/>scoped to the matched line span"}
    REF -->|rejected| SKIP
    REF -->|kept| FIND["Finding{rule, confidence}"]
    KEEP --> FIND
    LANG --> TAINT["cross-line taint<br/>12 sink specs, python + js only"]
    TAINT --> FIND
    FIND --> LOWA{"test / vendor / example path?"}
    LOWA -->|yes| DOWN["high → medium<br/>deny → ask"]
    LOWA -->|no| SORT
    DOWN --> SORT["sort: confidence, KEV, CWE rank"]
    SORT --> OUT["worst finding drives the decision"]
```

Two properties worth knowing when reading findings:

- **Only the top-sorted finding drives the decision.** A file with a medium and a
  high finding is decided by the high one; the medium is logged, not surfaced
  separately.
- **Refinements are line-span scoped.** A `reject_re` that would suppress a false
  positive only sees the lines the regex matched, so a sanitizer three lines above
  the sink does not suppress. This cuts both ways — see THREAT_MODEL §5.2 W9.

## 4. State model

Everything peephole persists, per project. There is no global state and no
cross-project index.

```mermaid
erDiagram
    PROJECT ||--|| MODE : "has"
    PROJECT ||--|| AUDIT : "has"
    PROJECT ||--o{ SESSION : "has many"
    PROJECT ||--o| POLICY : "may have"

    MODE {
        string mode "off|audit|guided|strict|hardened"
        string mode_sig "HMAC over mode, keyed by .modekey"
        string state_version "schema version for migration"
    }
    AUDIT {
        string log_jsonl "append-only decision entries"
        string log_head "running SHA-256 fold + count"
        string log_lock "advisory lockfile, 1ms spin, 200ms cap"
    }
    SESSION {
        string hunks "content hashes already decided"
        string wrote "a write occurred this session"
        string decisions "decision count, for the zero-decision alarm"
        string semreview "semantic classes the landed code touched"
        string reviewed "classes the Stop review already covered"
        string denies "deny-budget counters"
    }
    POLICY {
        string min_mode "floor — escalation only"
        string enforce "CWEs that must hard-deny"
    }
```

State is mode `0600` inside a `0700` directory, gitignored, and **writable by the
agent** — it is not a trust boundary (THREAT_MODEL §3 B4). The audit chain is
unkeyed, so it is evidence of record, not evidence against an adversary.

## 5. Integration topology

The engine is identical everywhere; only the transport and the strength of the
veto differ.

```mermaid
flowchart LR
    BIN["peephole binary"]
    subgraph HARD["Can veto a write pre-emptively"]
        H1["native pre-tool hook<br/>Claude Code JSON dialect"]
        H2["exit-code dialect --exit2<br/>Gemini · Codex · Qwen · Crush · Cursor"]
        H3["in-process plugin<br/>OpenCode"]
    end
    subgraph SOFT["Advisory only"]
        S1["MCP server<br/>scan_code tool"]
        S2["LSP diagnostics"]
    end
    subgraph BACKSTOP["Blocks later"]
        B1["git pre-commit<br/>scan --gate --staged"]
        B2["commit review<br/>PostToolUse on git commit"]
    end
    BIN --> H1 & H2 & H3 & S1 & S2 & B1 & B2

    style HARD fill:#0f3d2e,stroke:#2ea043,color:#e6edf3
    style SOFT fill:#3d2f0f,stroke:#d29922,color:#e6edf3
    style BACKSTOP fill:#1f2937,stroke:#6b7280,color:#e6edf3
```

**Important asymmetry between the two hard dialects.** The Claude Code JSON dialect
expresses three outcomes (`allow`/`ask`/`deny`). The exit-code dialect has two: `2`
blocks, everything else passes. So on exit-code hosts every `ask` becomes an
`rc=0` allow plus a stderr line, which means the `ask` tier — and the whole
uninspectable-write surface — is unenforced there. Since `guided` emits only
`ask`, **the default mode blocks nothing on exit-code hosts.**

## 6. Fleet deployment

```mermaid
flowchart TB
    subgraph DIST["Distribution"]
        REL["GitHub release<br/>5 platform binaries + SHA256SUMS<br/>gated: KB freshness · tests · version match · govulncheck -mode=binary"]
        SRC["build from source<br/>./build.sh — reproducible for a fixed toolchain"]
    end
    subgraph LAPTOP["Developer laptop"]
        BINL["/usr/local/bin/peephole"]
        HOOK[".claude/settings.json<br/>or plugin auto-registration"]
        ST[".peephole/ per project"]
        AV["endpoint agent<br/>⚠ inspects every state write:<br/>~4ms → ~15-50ms per event"]
    end
    CI["CI — Semgrep / CodeQL<br/>the actual blocking gate"]
    REL --> BINL
    SRC --> BINL
    BINL --> HOOK --> ST
    AV -.->|"exclude **/.peephole/"| ST
    ST -.->|"no egress — nothing ships anywhere"| X(("no central<br/>collection"))
    LAPTOP --> CI

    style AV fill:#3d1f1f,stroke:#f85149,color:#e6edf3
    style X fill:#1f2937,stroke:#6b7280,color:#e6edf3
```

Two facts a rollout plan must account for:

- **There is no telemetry.** No egress path exists in the codebase. A security team
  gets per-developer local logs with no file paths, no user identity, and no
  central view. Any fleet reporting must be built separately.
- **Exclude `**/.peephole/` from on-access scanning.** Peephole performs ~5–7 file
  operations per gated event; on an AV-managed endpoint each costs ~3–5ms instead
  of ~0.05ms, which is the entire difference between ~4ms and ~15–50ms per event.
  Rule evaluation itself is ~0.33ms.

## 7. Where peephole sits in a security program

```mermaid
flowchart LR
    A["Author time<br/><b>peephole guidance</b><br/>CWE context + exemplars"] --> B["Write time<br/><b>peephole gate</b><br/>~40% blocking recall"]
    B --> C["Commit time<br/>git pre-commit<br/>gitleaks"]
    C --> D["PR time<br/><b>Semgrep / CodeQL</b><br/>the blocking control"]
    D --> E["Runtime<br/>WAF · RASP · monitoring"]

    style A fill:#0f3d2e,stroke:#2ea043,color:#e6edf3
    style D fill:#0d3b66,stroke:#58a6ff,color:#e6edf3
```

Peephole owns the leftmost two stages and is strongest at the first. It does not
replace stage D — held-out blocking recall is ~40%, and whole classes (missing
authorization, broken business logic, cross-file dataflow) are outside what a
per-hunk engine can prove. Deploy it to reduce what reaches CI, not to replace CI.
