---
name: Bug report
about: A wrong decision, a crash, or unexpected behavior
title: ''
labels: bug
---

**What happened**
A clear description of the bug.

**Hook event (if applicable)**
The stdin JSON peephole received and the decision it emitted:

```json
{ "hook_event_name": "PreToolUse", "tool_name": "Write", "tool_input": { ... } }
```

```
observed: permissionDecision = ...
expected: ...
```

**Mode**: guided / audit / strict / hardened / off

**Environment**: OS + arch, peephole version (`plugin.json` version or commit).

**Security note**: if this is an enforcement/self-protection *bypass*, please
report it privately per [SECURITY.md](../../SECURITY.md) instead.
