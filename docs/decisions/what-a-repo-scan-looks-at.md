---
enola_intent:
  page:
    type: decision
    status: living
    scope: [augur]
    origin: [repo]
    relations:
      - {rel: relates-to, to: docs/decisions/verify-what-we-write.md}
    anchors:
      - {repo: augur, path: internal/walk}
      - {repo: augur, path: internal/cli}
---

# A repository scan says what it did not look at

**Status: living.**

`augur scan FILE` answers a question about one file. `augur scan .` answers a different
one — what is in this repository — and the dangerous part of that answer is not the
findings. It is the four hundred lines saying nothing was found, some of which mean
nobody looked.

So a directory scan reports coverage before it reports findings, and every path it
declined is counted with the reason it declined.

## Where the file list comes from

Inside a git worktree, from `git ls-files --cached --others --exclude-standard`: tracked
files, plus untracked files that are not ignored. Outside one — or under `--no-git` — from
a filesystem walk that skips the directory names in `walk.SkipDir`.

Shelling out to git rather than implementing `.gitignore` is deliberate. Ignore rules nest
per directory, compose with `.git/info/exclude` and the user's global excludes, and
support negation. A second implementation of that is a second set of bugs, and every one
of them surfaces as augur reading a file the user believed was ignored or skipping one
they believed was not. git already knows.

The consequence, stated because it is a real one: a **tracked** file inside `node_modules`
or `vendor` is scanned. git's answer is authoritative inside a repository and the skip
list is not consulted there. A tracked vendored file is part of the repository, and
declining to look at something git tracks would be exactly the silent blind spot this
page exists to prevent.

## What is not opened, and how it is reported

Four reasons, each counted in the summary and named per path in `--json`:

- **larger than the size limit** — the walk caps files at 10 MiB (`--max-size`), because a
  directory scan reads files concurrently and the ceiling is per worker. A file named
  directly on the command line is never capped: the user asked for that one.
- **symbolic link** — not followed. The target is either already inside the tree or
  outside it on purpose, and following links is how one scan becomes a scan of the disk.
- **submodule** — one entry that is a directory. Scan it as its own repository.
- **could not be read** — and this makes the run exit 2, never 0.

## Examined is not the same as clean

A format no handler claims exposes no text regions, so every text detector iterates an
empty list and the file comes back with no findings. `scan.Result.Examined()` separates
the two, and the report prints `N not examined (no handler reads their format)` on its
own line. `TestExaminedMatchesTheHandlers` derives the expected answer from the detector
registry, so adding a handler for a new format cannot leave that count lying.

## The severity floor

A directory scan reports `concern` and above by default; a named file still reports
everything. This is the same reasoning `augur agents` uses, and it is stronger at
repository scale: notice-level trailing whitespace and byte-order marks are a linter's
business, and a few thousand of them bury the one decoded payload that is the reason this
tool exists. The floor is stated in the report along with the number of findings it hid,
and `--min-severity=notice` lifts it.

## Not in scope: cleaning a tree

`augur clean` takes one file and writes a new one beside it, and never opens the original
for writing — see [lossless-only.md](lossless-only.md) and
[verify-what-we-write.md](verify-what-we-write.md). Neither half of that survives contact
with a repository: three hundred `.clean` copies are useless, and the only shape that is
not useless is rewriting files in place, which trades away the property that the original
is still there to compare against.

That trade may be worth making later, gated on a clean worktree so git holds the original
instead. It is not made here. `augur scan DIR` reports; it does not write.
