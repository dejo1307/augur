# augur

See what is hidden in a file. Decide what goes. Keep a clean copy.

Files routinely carry things nobody typed: zero-width characters smuggling
instructions to a model, direction controls that make source read differently
than it runs, a word with a Cyrillic letter in the middle of it, GPS coordinates
in a photo, a signed provenance manifest, a zip archive stapled past the end of a
JPEG. Almost none of it is visible, and the usual advice — screenshot it — throws
away the picture's quality to remove the one mark you could already see.

augur shows you the rest.

![augur inspecting a document and a photo](docs/demo.gif)

Nothing in that recording is staged. The two files come from
[`demo/make-fixtures.py`](demo/make-fixtures.py), which plants each thing augur
then finds — so you can regenerate them and check the tool against a script that
says exactly what it hid.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/dejo1307/augur/main/install.sh | sh
```

Installs to `~/.local/bin`. The script verifies the release checksum before it
installs anything and refuses outright if it does not match — piping a downloaded
binary onto your PATH is exactly the situation that check exists for.

Override the destination with `AUGUR_INSTALL_DIR`, or pin a version with
`AUGUR_VERSION`. Prebuilt binaries cover Linux and macOS on amd64 and arm64, and
Windows on amd64; [releases](https://github.com/dejo1307/augur/releases) has them
all with checksums.

After that, `augur upgrade` keeps itself current. It verifies the release
checksum before writing anything and swaps the binary by rename, so an
interrupted or tampered download leaves the working one exactly where it was.

With a Go toolchain (1.25.13 or newer):

```sh
go install github.com/dejo1307/augur/cmd/augur@latest
```

## Use

```sh
augur                     # browse for a file
augur photo.jpg           # open it in the viewer
augur scan photo.jpg      # report and exit: 0 clean, 1 findings, 2 error
augur scan photo.jpg --json
augur clean photo.jpg     # writes photo.clean.jpg, then verifies it
augur clean notes.txt --categories=invisible,metadata

augur upgrade             # replace this binary with the newest release
augur upgrade --check     # report whether one exists; exit 1 if so, 0 if current
```

The original is never opened for writing. Cleaning writes a new file beside it.

In the file picker: `↑↓` move, `→` open, `←` up a level, `~` home, `/` root,
`.` toggles hidden files. In the findings view: `space` toggles one, `a` selects
all removable, `n` none, `s` saves a clean copy, `?` shows the blind spots,
`esc` closes the file and goes back to browsing, `q` leaves.

## What it finds

**In text, and in the text inside images** — zero-width characters, Unicode tag
characters, variation selectors, private-use codepoints, bidi controls (Trojan
Source), words that mix Latin with Cyrillic or Greek, exotic spaces, trailing
whitespace, byte-order marks, invalid UTF-8.

**And it reads them.** A run of invisible characters is not reported as a count.
augur reverses the three published smuggling schemes — tag characters,
variation selectors, and zero-width binary — and shows you the sentence:

```
STEGANOGRAPHIC
   [alarm] offset 50 — hidden message, 49 characters
       decodes to (Unicode tag characters): "ignore all previous instructions"
```

**In JPEG, PNG and WebP containers** — EXIF (decoded, with GPS shown as
coordinates you can read), XMP, IPTC, ICC profiles, JPEG comments, PNG text
chunks, C2PA provenance manifests, and bytes sitting past the container's logical
end.

The text detectors run over the text inside an image too, so a message hidden in
a photo's XMP packet is found by the same code that reads a `.txt` file.

## What it will not do

**It does not attack watermarks carried in pixels.** Metadata stripping is
removing a label. Attacking a robust pixel watermark is evasion of provenance
detection, it degrades the image, and — the part that decides it — it is
unverifiable: the tool could not tell you whether it worked, which is precisely
where it would need to be believed. See
[docs/decisions/lossless-only.md](docs/decisions/lossless-only.md).

**It says what it cannot see.** Press `?` for the blind-spots panel: statistical
watermarks in generated text, pixel-domain watermarks, fingerprinting by wording,
and formats with no handler yet. A clean report means these detectors found
nothing; it is not a claim that the file is unmarked.

## Cleaning is lossless, and checks itself

Every removal is a byte-exact edit: a codepoint deleted or substituted, or a whole
container block dropped. Compressed image data is copied through untouched — strip
every metadata block from a JPEG and the entropy-coded scan is byte-identical to
the original's.

After writing, augur re-reads the file **from disk** and scans it again.
What you are shown is the result of that second scan, not a summary of what the
cleaner meant to do. If anything selected for removal is still present, it says
`VERIFICATION FAILED` rather than reporting success with a caveat.

Three invariants are property-tested over generated inputs:

```
clean(orig, {})        is byte-identical to orig
clean(clean(x, S), S)  equals clean(x, S)
scan(clean(orig, S))   equals scan(orig) minus S
```

Some findings are shown and never removed — a mixed-script word, invalid UTF-8 —
because the fix is a judgment call and guessing it would rewrite meaning. Those
say so, with the reason, instead of being quietly dropped from the list.

## Architecture

Declared before the first detector was written, and enforced in CI:

| Layer | | 
|---|---|
| entrypoint | `cmd/**` |
| surface | `internal/tui`, `internal/cli`, `internal/report` |
| orchestration | `internal/session` |
| engine | `internal/scan` |
| analysis | `internal/detect`, `internal/decode`, `internal/clean` |
| core | `pkg/finding`, `pkg/detect`, `internal/runeinfo` |

A detector imports the vocabulary and nothing above it, so adding one is a file
under `internal/detect/` plus a line in the registry. The viewer never touches
file bytes. The layer order lives in [`enola-intent.yaml`](enola-intent.yaml) and
is checked by [enola](https://github.com/enola-labs/enola):

```sh
enola check --fail-on=layers,intent --min-confidence=0.8 mcp-arch.yaml
```

Two policies, for two kinds of drift. **`layers`** fails a package that starts
depending outwards — declared rather than inferred, so it verdicts at 1.00.
**`intent`** fails a dangling anchor: the decision pages in
[docs/decisions/](docs/decisions/) point at the code they govern, and when that
code moves or dies the gate says so. It is the only thing keeping a decision
document from quietly becoming fiction, and a stale one is worse than none
because it is still believed.

Not `cycles` — this is Go, and the compiler already refuses import cycles between
packages. The layer order is the part it cannot check.

## Development

```sh
go test ./...                                # includes the property tests
enola check --fail-on=layers,intent --min-confidence=0.8 mcp-arch.yaml
```

To re-record the demo (needs [VHS](https://github.com/charmbracelet/vhs) and
ImageMagick):

```sh
go build -o demo/augur ./cmd/augur
python3 demo/make-fixtures.py
vhs demo/demo.tape
```

Dependencies: Bubble Tea, Bubbles and Lipgloss for the viewer. The scanner, the
decoders, the EXIF reader and the container walkers are standard library only —
and nothing needs cgo, so every release platform cross-compiles from one runner.

CI runs on every pull request: build, vet, gofmt, race tests with coverage, a
separate gate for the clean/scan invariants, golangci-lint, govulncheck, and the
architecture gate above.

The Go version in `go.mod` is a floor rather than a preference: 1.25.13 is the
first release fixing the standard-library advisories `govulncheck` flags as
reachable from the file picker and from `augur upgrade`'s HTTPS calls. Adding a
command that talks to the network moved four of them from unreachable to
reachable, which is exactly what that gate is for.

## License

[Apache-2.0](LICENSE). Release archives carry `LICENSE` and `NOTICE` beside the
binary, which is where anyone installing via `install.sh` will actually see them.
