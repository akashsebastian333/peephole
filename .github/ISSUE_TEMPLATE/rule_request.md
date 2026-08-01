---
name: Rule request / false positive / false negative
about: Propose a new detection, or report a rule that over- or under-matches
title: ''
labels: rule
---

**CWE / class**: e.g. CWE-89 SQL Injection (or "new class")

**Language(s)**: python / javascript / go / ...

**Vulnerable example (should be flagged)**
```
<code>
```

**Safe example (must NOT be flagged)**
```
<code>
```

**Current behavior**: not flagged / wrongly flagged / flagged with wrong severity

**Attack scenario** (one sentence): how is it exploited?

**Suggested RE2 pattern** (optional): remember, no lookaround/backreferences —
use `prev_not` / `reject_re` / `require_re` refinements instead.
