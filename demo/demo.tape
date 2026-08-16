# augur demo — recorded with https://github.com/charmbracelet/vhs
#
#   go build -o demo/augur ./cmd/augur
#   python3 demo/make-fixtures.py
#   vhs demo/demo.tape
#
# The fixtures are built by make-fixtures.py, so everything on screen is real
# detection of things that script deliberately planted — not a staged mockup.

Output docs/demo.gif

Set Shell zsh
Set FontSize 15
Set Width 1300
Set Height 620
Set Padding 20
Set Theme "TokyoNight"
Set TypingSpeed 55ms
Set Framerate 24

Hide
Type "export PATH=$PWD/demo:$PATH && clear"  Enter
Show

# --- a document that came out of a chat assistant --------------------------
Sleep 800ms
Type "augur demo/q3-summary.txt"  Sleep 400ms  Enter
Sleep 3s

# an invisible character, then the homoglyph that is shown but never auto-fixed
Down@500ms 1
Sleep 2.2s
Down@500ms 1
Sleep 2.5s

# save a clean copy — augur re-reads it from disk and verifies
Type "s"
Sleep 3.5s

# back to the findings, then close the file without leaving the app
Escape
Sleep 600ms
Escape
Sleep 1.4s

# --- now a photo -----------------------------------------------------------
Type "q"
Sleep 500ms
Type "clear"  Enter
Sleep 400ms

Type "augur demo/holiday-photo.jpg"  Sleep 400ms  Enter
Sleep 3s

# a zip archive stapled past the end of the image
Down@500ms 1
Sleep 2.2s

# EXIF: camera, serial number, and where the photo was taken
Down@500ms 2
Sleep 3.2s

# provenance, shown and labelled rather than editorialised
Down@500ms 3
Sleep 2.8s

# what augur cannot see, said out loud
Type "?"
Sleep 2.5s
Down@120ms 14
Sleep 2.5s

Escape
Sleep 400ms
Type "q"
Sleep 800ms
