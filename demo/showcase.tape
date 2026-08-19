# augur showcase — the long-form recording, for posting rather than for the README.
#
#   go build -o demo/augur ./cmd/augur
#   python3 demo/make-fixtures.py
#   python3 demo/make-agent-fixtures.py
#   vhs demo/showcase.tape
#
#   # VHS leaves the moov atom at the end of the file, so a player has to
#   # fetch the whole thing before it can start. This is a stream copy —
#   # nothing is re-encoded — and it matters for anywhere the video is
#   # streamed rather than downloaded.
#   ffmpeg -i demo/augur-showcase.mp4 -c copy -movflags +faststart out.mp4
#
# Writes demo/augur-showcase.mp4 at 1920x1080, H.264 High / yuv420p, no audio.
#
# Nothing here is staged. The two files in act one and two are built by
# make-fixtures.py and the agent workspace in act three and four by
# make-agent-fixtures.py, both of which say in source exactly what they plant.
#
# The workspace matters for a second reason: `augur agents` reads the real
# ~/.claude of whoever runs it, so this tape points HOME at a generated sandbox.
# Recording it against a live machine would publish that machine's instruction
# files.

Output demo/augur-showcase.mp4

Set Shell zsh
Set FontSize 24
Set Width 1920
Set Height 1080
Set Padding 40
Set Theme "TokyoNight"
Set TypingSpeed 40ms
Set Framerate 30

# A prompt of our own, from a shell that read no rc file — so nothing about the
# machine this was recorded on ends up on screen.
Hide
Type "exec zsh -f"  Enter
Sleep 500ms
Type "PROMPT='%F{4}❯%f ' && export PATH=$PWD/demo:$PATH && clear"  Enter
Sleep 500ms
Show

# ===========================================================================
# One — a document that came out of a chat assistant.
# ===========================================================================
Sleep 1.2s
Type "augur demo/q3-summary.txt"  Sleep 500ms  Enter
Sleep 3.5s

# the smuggled instruction, read back rather than counted
Sleep 1.5s

# an invisible character, then the homoglyph that is shown but never auto-fixed
Down@500ms 1
Sleep 2.5s
Down@500ms 1
Sleep 3s

# save a clean copy — augur re-reads it from disk and scans it again
Type "s"
Sleep 4s

Escape
Sleep 700ms
Escape
Sleep 1.2s
Type "q"
Sleep 600ms
Type "clear"  Enter
Sleep 500ms

# ===========================================================================
# Two — a photo.
# ===========================================================================
Type "augur demo/holiday-photo.jpg"  Sleep 500ms  Enter
Sleep 3.5s

# a zip archive stapled past the end of the image
Down@500ms 1
Sleep 2.5s

# EXIF: camera, owner, serial number, and where the photo was taken
Down@500ms 2
Sleep 3.5s

# provenance, shown and labelled rather than editorialised
Down@500ms 3
Sleep 3s

# what augur cannot see, said out loud
Type "?"
Sleep 2.5s
Down@120ms 14
Sleep 3s
Escape
Sleep 500ms
Type "q"
Sleep 600ms
Type "clear"  Enter
Sleep 500ms

# ===========================================================================
# Three — the files a coding agent reads as instructions.
#
# A sandboxed home and project, built by make-agent-fixtures.py. Everything the
# scan reports was planted by that script.
# ===========================================================================
Hide
Type "export HOME=$PWD/demo/workspace/home && cd demo/workspace/project && clear"  Enter
Sleep 500ms
Show

Sleep 800ms
Type "augur agents --list"  Sleep 500ms  Enter
Sleep 5s
Type "clear"  Enter
Sleep 400ms

Type "augur agents"  Sleep 500ms  Enter
Sleep 9s
Type "clear"  Enter
Sleep 400ms

# ===========================================================================
# Four — a whole repository, and the coverage it reports before the findings.
# ===========================================================================
Type "augur scan ."  Sleep 500ms  Enter
Sleep 7s

Type "echo $?"  Sleep 300ms  Enter
Sleep 2.5s
