---
enola_intent:
  page:
    type: decision
    status: living
    scope: [augur]
    origin: [repo]
    relations:
      - {rel: relates-to, to: docs/decisions/lossless-only.md}
    anchors:
      - {repo: augur, path: pkg/detect}
      - {repo: augur, path: internal/detect}
      - {repo: augur, path: internal/decode}
---

# A detector knows facts and nothing above them

**Status: living.**

Adding a detector is one file under `internal/detect/` plus one registry line. It must not
require touching the engine, the session, or the TUI, and it must not be able to.

## The contract

A detector receives a `detect.Source` — the file's bytes, its sniffed format, and any text
regions a format handler exposed — and returns `[]finding.Finding`. It imports `pkg/finding`
and `pkg/detect` and nothing else from this module. The layer order in `enola-intent.yaml`
enforces that: `internal/detect/**` sits in `analysis`, and `analysis` may not depend on
`engine`, `orchestration`, or `surface`.

## Why the rule is worth enforcing rather than intending

The interesting content of this tool is the long tail: each new smuggling scheme, each new
metadata container, each new invisible codepoint block. That tail only stays cheap to extend
if writing entry number forty costs the same as entry number four. The moment a detector can
reach into the engine to ask a question, every subsequent detector will, and the fortieth
one costs a design discussion.

## Region offsets, and the honest half of the contract

A `Region` is either **inline** — its text is a verbatim slice of the file at a known
offset, so a finding's span maps back to real bytes and a span edit is exact — or
**derived**, meaning the text was decompressed or re-decoded on the way out (a PNG `zTXt`
chunk, say). Findings in a derived region are real and are reported, but their spans do not
address file bytes. They are either `Removable: false` or removable only by the format
handler dropping the whole chunk.

Detectors do not get to blur this. A detector that cannot say where something is says so,
and the engine will not pretend otherwise on its behalf.
