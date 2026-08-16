---
enola_intent:
  page:
    type: decision
    status: living
    scope: [augur]
    origin: [repo]
    relations:
      - {rel: depends-on, to: docs/decisions/lossless-only.md}
    anchors:
      - {repo: augur, path: internal/session}
---

# The tool checks its own work

**Status: living.**

After writing a cleaned copy, augur re-reads that file **from disk** and scans
it again with the same detectors that produced the findings in the first place. The
result of that second scan is what the user is shown — not a summary of what the
cleaner intended to do.

## Why it is done this way rather than the obvious way

The obvious implementation reports the selection: *you asked for six things to be
removed, six things were removed.* That sentence is true even when the cleaner is
broken, because it is a statement about the request rather than about the file. Every
class of bug this tool could plausibly have — an off-by-one span, a container length
field left stale, an edit applied to the wrong copy of the buffer — produces a
correct-looking report under that design and a damaged file on disk.

Re-reading is also specifically re-reading, not re-scanning the buffer that was
written. The buffer is what we believe we wrote. The file is what we wrote.

## What it produces

`Verification` carries three things, and the third is the one that matters:

- `Removed` — how many findings the clean was meant to take out
- `Remaining` — what the fresh scan still finds, which is expected to be non-empty
  whenever the user deliberately left something in place
- `Leaked` — findings that were selected for removal and are *still there*

`Leaked` should always be empty. When it is not, the viewer says
`VERIFICATION FAILED` and the CLI exits non-zero. It never reports success and
quietly attaches a caveat.

## The invariants underneath it

The same guarantee is property-tested rather than left to the runtime check:

```
clean(orig, {})        is byte-identical to orig
clean(clean(x, S), S)  equals clean(x, S)
scan(clean(orig, S))   equals scan(orig) minus S
```

The second one is worth a note, because it was the hardest to hold. Removing an
invisible character can expose whitespace that was previously not at the end of a
line, and removing a direction control can do the same — so an early version needed
two passes to settle and would have reported a file as verified while a re-scan
disagreed. The fix was to give the detectors a shared, text-derived notion of the
end-of-line zone rather than to run the cleaner twice: converging by construction is
checkable, and converging by repetition only hides how far it was from converging.

## The original is never opened for writing

There is no code path that opens the inspected file for writing, and `Save` refuses
a destination that resolves to the same file. That is what makes every other claim
here recoverable: if the tool is wrong, the evidence is still on disk.
