---
enola_intent:
  page:
    type: decision
    status: living
    scope: [augur]
    origin: [repo]
    relations:
      - {rel: relates-to, to: docs/decisions/detector-contract.md}
    anchors:
      # The decision is encoded in the Finding model: `Removable` exists precisely
      # because some things are shown and never taken out.
      - {repo: augur, path: pkg/finding}
      - {repo: augur, path: internal/clean}
      - {repo: augur, path: internal/detect/image}
---

# Cleaning is lossless, or it does not happen

**Status: living. Decided before the first detector was written.**

augur removes only what it can remove **byte-exactly**: individual codepoints from a
text file, and whole segments or chunks from an image container. It never re-encodes pixel
data, and it never attempts to defeat a watermark carried in the pixels themselves.

## Why

Two reasons. The weaker one first.

**It would be unverifiable.** Every other promise this tool makes is checkable: it re-scans
what it wrote and shows you the result. A pixel-domain attack has no such check. The tool
could not tell you whether the watermark survived, so it would be asking for trust exactly
where it had nothing to offer — which is the failure mode the whole product exists to fix.

**It would be a different product.** Detecting a mark and telling you it is there is
transparency. Stripping metadata is privacy, and every social network already does it on
upload. Attacking a robust pixel watermark is neither: it is purpose-built evasion of
provenance detection, and it degrades the image while it does it. That is not a tool about
seeing what is in your files.

## What this means concretely

- Compressed image data is copied through untouched. A cleaned JPEG's entropy-coded scan is
  byte-identical to the original's.
- **Documents are read and never written.** PDFs and Office files are parsed in full — hidden
  runs, invisible text, tracked changes, properties, the revisions an incremental save left
  behind — and every finding in one is `Removable: false`. A PDF records the byte offset of
  every object in a cross-reference table and an Office file is a deflated archive, so there is
  no edit that removes a run without rebuilding the file around it. A rebuilt document is a
  different file with the same contents, and the tool cannot check it against the original the
  way it checks an edited one, which is the whole basis of
  [verify-what-we-write](verify-what-we-write.md). Reporting without offering to fix is the
  honest position, and it is stated in the finding rather than left to be discovered.
- Provenance is **shown, labelled, and removable like any other container segment** — a
  C2PA manifest is metadata in a box, and a user who understands what they are removing is
  entitled to remove it. What the tool will not do is pretend a re-encode achieved something
  it cannot measure.
- Anything found but not losslessly removable is reported with `Removable: false` and an
  explanation, rather than quietly omitted from the findings list.

## The boundary, stated out loud

There are marks augur structurally cannot see: statistical token watermarks in
generated text (they need the generator's key), pixel-domain watermarks, and semantic
fingerprinting. The tool ships a blind-spots panel that says so. A tool implying that
"clean" means "clean of everything" is lying, and this one is built to be believed.
