// Package tui is the interactive viewer: the surface a person uses.
//
// It renders findings and sends selections to a session. It never opens a file,
// never edits bytes, and holds no opinion about what anything means — every
// sentence it shows was written by the detector that found the thing. That
// separation is what lets the same behaviour ship as `augur scan` with no
// duplicated logic.
package tui

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/filepicker"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/dejo1307/augur/internal/report"
	"github.com/dejo1307/augur/internal/session"
	"github.com/dejo1307/augur/pkg/finding"
)

type screen int

const (
	screenPicker screen = iota
	screenFindings
	screenBlindSpots
	screenSaved
)

// Model is the viewer's whole state.
type Model struct {
	screen screen

	picker filepicker.Model
	detail viewport.Model

	sess   *session.Session
	rows   []row // the flattened list: category headers and findings
	cursor int

	saved  *session.Verification
	status string
	err    error

	width, height int
	quitting      bool
}

// row is one line of the left-hand list. Headers are not selectable, which keeps
// the grouping visible without turning the cursor into a special case everywhere.
type row struct {
	header   string
	category finding.Category
	f        finding.Finding
}

func (r row) isHeader() bool { return r.header != "" }

// newPicker builds a file picker rooted at dir, falling back to the working
// directory. Shared by the initial launch and by closing a file, so browsing
// behaves identically however you arrived at it.
func newPicker(dir string) filepicker.Model {
	fp := filepicker.New()
	fp.ShowHidden = false
	if dir == "" {
		dir, _ = filepath.Abs(".")
	}
	fp.CurrentDirectory = dir
	return fp
}

// New builds the viewer. An empty path opens the file picker.
func New(path string) (Model, error) {
	m := Model{detail: viewport.New(0, 0)}
	if path == "" {
		m.picker = newPicker("")
		m.screen = screenPicker
		return m, nil
	}
	if err := m.open(path); err != nil {
		return m, err
	}
	return m, nil
}

// closeFile returns to the picker without leaving the program, positioned in the
// directory of the file that was open.
//
// Quitting is not the only reason to be done with a file, and it was previously
// the only way to express it — so inspecting three files meant starting the
// program three times. Landing back where the file was is the useful default:
// the next file someone wants to check is usually its neighbour.
func (m Model) closeFile() (tea.Model, tea.Cmd) {
	dir := ""
	if m.sess != nil {
		dir = filepath.Dir(m.sess.Path)
	}
	m.picker = newPicker(dir)
	m.picker.SetHeight(m.pickerHeight())
	m.screen = screenPicker
	m.sess = nil
	m.rows = nil
	m.cursor = 0
	m.saved = nil
	m.status = ""
	return m, m.picker.Init()
}

func (m *Model) open(path string) error {
	s, err := session.Open(path)
	if err != nil {
		return err
	}
	m.sess = s
	m.screen = screenFindings
	m.saved = nil
	m.status = ""
	m.rebuild()
	m.cursor = m.firstSelectable()
	return nil
}

// rebuild flattens the finding set into display rows, grouped by category in
// severity order.
func (m *Model) rebuild() {
	m.rows = nil
	byCat := m.sess.Findings().ByCategory()
	for _, cat := range finding.Categories() {
		group := byCat[cat]
		if len(group) == 0 {
			continue
		}
		m.rows = append(m.rows, row{header: string(cat), category: cat})
		for _, f := range group {
			m.rows = append(m.rows, row{f: f})
		}
	}
}

func (m Model) firstSelectable() int {
	for i, r := range m.rows {
		if !r.isHeader() {
			return i
		}
	}
	return 0
}

func (m Model) Init() tea.Cmd {
	if m.screen == screenPicker {
		return m.picker.Init()
	}
	return nil
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.detail.Width = m.detailWidth()
		m.detail.Height = m.bodyHeight()
		m.picker.SetHeight(m.pickerHeight())
		m.refreshDetail()
		return m, nil

	case tea.KeyMsg:
		switch m.screen {
		case screenPicker:
			return m.updatePicker(msg)
		case screenBlindSpots:
			// The panel is longer than most terminals, so it has to scroll.
			// "Any key goes back" on its own made its bottom half unreachable —
			// which, on the one screen whose whole job is to be complete about
			// the tool's limits, is the worst place to hide half the content.
			switch msg.String() {
			case "up", "k":
				m.detail.ScrollUp(1)
				return m, nil
			case "down", "j":
				m.detail.ScrollDown(1)
				return m, nil
			case "pgup":
				m.detail.HalfPageUp()
				return m, nil
			case "pgdown", " ":
				m.detail.HalfPageDown()
				return m, nil
			}
			m.screen = screenFindings
			m.refreshDetail()
			return m, nil
		case screenSaved:
			if msg.String() == "q" || msg.String() == "ctrl+c" {
				m.quitting = true
				return m, tea.Quit
			}
			m.screen = screenFindings
			return m, nil
		default:
			return m.updateFindings(msg)
		}
	}

	if m.screen == screenPicker {
		var cmd tea.Cmd
		m.picker, cmd = m.picker.Update(msg)
		return m, cmd
	}
	return m, nil
}

func (m Model) updatePicker(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	// Jumps. Walking up one directory at a time from wherever the shell happened
	// to be is a long way from ~/Downloads, which is where the file you want to
	// inspect usually is.
	case "~":
		return m.goTo(homeDir())
	case "/":
		return m.goTo("/")
	case ".":
		m.picker.ShowHidden = !m.picker.ShowHidden
		return m, m.picker.Init()
	}

	var cmd tea.Cmd
	m.picker, cmd = m.picker.Update(msg)
	if ok, path := m.picker.DidSelectFile(msg); ok {
		if err := m.open(path); err != nil {
			m.err = err
			return m, cmd
		}
		m.detail.Width, m.detail.Height = m.detailWidth(), m.bodyHeight()
		m.refreshDetail()
	}
	return m, cmd
}

func (m Model) updateFindings(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	// Two separate exits, because they are two separate intentions: esc closes
	// the file and goes back to browsing, q leaves the program.
	case "esc", "backspace", "left":
		return m.closeFile()

	case "q":
		m.quitting = true
		return m, tea.Quit

	case "up", "k":
		m.moveCursor(-1)
	case "down", "j":
		m.moveCursor(1)
	case "pgup":
		for i := 0; i < 10; i++ {
			m.moveCursor(-1)
		}
	case "pgdown":
		for i := 0; i < 10; i++ {
			m.moveCursor(1)
		}

	case " ":
		if r := m.current(); r != nil && !r.isHeader() {
			m.sess.Toggle(r.f.ID)
			m.status = ""
		}
	case "a":
		m.sess.SelectAll()
		m.status = ""
	case "n":
		m.sess.SelectNone()
		m.status = ""

	case "?":
		// The blind-spots panel is a full-screen view, so it gets the full width.
		// The split-pane width is restored when the detail pane comes back.
		m.screen = screenBlindSpots
		m.detail.Width = maxInt(20, m.width-4)
		m.detail.SetContent(blindSpots())
		m.detail.GotoTop()
		return m, nil

	case "s":
		return m.save()

	case "J":
		m.detail.ScrollDown(1)
		return m, nil
	case "K":
		m.detail.ScrollUp(1)
		return m, nil
	}

	m.refreshDetail()
	return m, nil
}

func (m Model) save() (tea.Model, tea.Cmd) {
	if m.sess.SelectionCount() == 0 {
		m.status = "nothing selected — space toggles a finding, a selects everything removable"
		return m, nil
	}
	dest := session.DefaultDest(m.sess.Path)
	v, err := m.sess.Save(dest, false)
	if err != nil {
		m.status = "could not save: " + err.Error()
		return m, nil
	}
	m.saved = &v
	m.screen = screenSaved
	return m, nil
}

func (m *Model) moveCursor(delta int) {
	i := m.cursor
	for {
		i += delta
		if i < 0 || i >= len(m.rows) {
			return // do not wrap: the ends of a findings list are meaningful
		}
		if !m.rows[i].isHeader() {
			m.cursor = i
			return
		}
	}
}

func (m Model) current() *row {
	if m.cursor < 0 || m.cursor >= len(m.rows) {
		return nil
	}
	return &m.rows[m.cursor]
}

func (m *Model) refreshDetail() {
	if m.screen != screenFindings {
		return
	}
	m.detail.Width = m.detailWidth()
	r := m.current()
	if r == nil || r.isHeader() {
		m.detail.SetContent("")
		return
	}
	m.detail.SetContent(renderDetail(r.f, m.detailWidth()))
	m.detail.GotoTop()
}

// ---------------------------------------------------------------------------
// layout
// ---------------------------------------------------------------------------

func (m Model) listWidth() int {
	w := m.width * 45 / 100
	if w < 32 {
		w = 32
	}
	if w > 60 {
		w = 60
	}
	return w
}

// paneChrome is what styPane spends on its left border and padding. Text is
// wrapped to the width inside that, not the width of the pane — otherwise every
// line sits three characters too long and lipgloss re-wraps it, leaving a stray
// word alone on the next line.
const paneChrome = 3

func (m Model) detailWidth() int {
	w := m.width - m.listWidth() - paneChrome - 2
	if w < 20 {
		w = 20
	}
	return w
}

// pickerHeight leaves room for the picker's own chrome: a title, the current
// path, a rule and the help line.
func (m Model) pickerHeight() int {
	h := m.height - 7
	if h < 5 {
		h = 5
	}
	return h
}

func (m Model) bodyHeight() int {
	h := m.height - 5 // header, rule, help
	if h < 5 {
		h = 5
	}
	return h
}

func (m Model) View() string {
	if m.quitting {
		return ""
	}
	if m.err != nil {
		return "\n  " + styAlarm.Render("augur: "+m.err.Error()) + "\n\n  " +
			styHelp.Render("q to quit") + "\n"
	}

	switch m.screen {
	case screenPicker:
		return m.viewPicker()
	case screenBlindSpots:
		return m.header() + "\n" + m.detail.View() + "\n" + styHelp.Render("  ↑↓ scroll · any other key to go back")
	case screenSaved:
		return m.viewSaved()
	default:
		return m.viewFindings()
	}
}

// goTo moves the picker to a directory and re-reads it.
func (m Model) goTo(dir string) (tea.Model, tea.Cmd) {
	if dir == "" {
		return m, nil
	}
	m.picker.CurrentDirectory = dir
	return m, m.picker.Init()
}

func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// shortenPath renders the home directory as ~, the way every shell prompt does.
func shortenPath(p string) string {
	if h := homeDir(); h != "" && strings.HasPrefix(p, h) {
		return "~" + strings.TrimPrefix(p, h)
	}
	return p
}

func (m Model) viewPicker() string {
	// The current directory is shown for a reason beyond decoration: without it
	// there is no feedback that going up worked, so a picker that navigates
	// perfectly well reads as one that is stuck in the directory it started in.
	where := styPath.Render(shortenPath(m.picker.CurrentDirectory))

	hidden := "off"
	if m.picker.ShowHidden {
		hidden = "on"
	}

	return "\n" + styTitle.Render("  augur") +
		styFaint.Render(" — choose a file to inspect") + "\n" +
		"  " + where + "\n" +
		styRule.Render("  "+strings.Repeat("─", maxInt(10, m.width-4))) + "\n" +
		m.picker.View() + "\n" +
		styHelp.Render("  ↑↓ move · → open · ← up a level · ~ home · / root · . hidden ("+hidden+") · q quit") + "\n"
}

func (m Model) header() string {
	if m.sess == nil {
		return ""
	}
	name := filepath.Base(m.sess.Path)
	set := m.sess.Findings()

	verdict := styOK.Render("nothing hidden found")
	if len(set) > 0 {
		worst, _ := set.Worst()
		verdict = severityStyle(worst).Render(fmt.Sprintf("%d finding(s)", len(set)))
	}

	line := fmt.Sprintf("  %s %s  %s  %s",
		styPath.Render(name),
		styFaint.Render(fmt.Sprintf("· %s · %s", m.sess.Result.Source.Format, humanBytes(len(m.sess.Original)))),
		styRule.Render("│"),
		verdict,
	)
	sel := m.sess.SelectionCount()
	line += styFaint.Render(fmt.Sprintf("  ·  %d selected for removal", sel))
	return "\n" + line + "\n" + styRule.Render("  "+strings.Repeat("─", maxInt(10, m.width-4)))
}

func (m Model) viewFindings() string {
	body := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(m.listWidth()).Height(m.bodyHeight()).Render(m.viewList()),
		styPane.Width(m.detailWidth()+paneChrome).Height(m.bodyHeight()).Render(m.detail.View()),
	)

	help := "  space toggle · a all · n none · s save clean copy · ? blind spots · esc close file · q quit"
	if m.status != "" {
		help = "  " + styWarn.Render(m.status)
	}
	return m.header() + "\n" + body + "\n" + styHelp.Render(help)
}

func (m Model) viewList() string {
	var b strings.Builder

	// Keep the cursor in view without a full scrolling list component: the window
	// is a simple slice around the cursor.
	h := m.bodyHeight()
	start := 0
	if m.cursor >= h-1 {
		start = m.cursor - h + 2
	}
	end := minInt(len(m.rows), start+h)

	for i := start; i < end; i++ {
		r := m.rows[i]
		if r.isHeader() {
			b.WriteString(styCategory.Render("  " + strings.ToUpper(r.header)))
			b.WriteString("\n")
			continue
		}

		cursor := "  "
		if i == m.cursor {
			cursor = styCursor.Render("▸ ")
		}

		box := styFaint.Render("·") // not removable
		if r.f.Removable {
			box = "○"
			if m.sess.Selected(r.f.ID) {
				box = styOK.Render("✓")
			}
		}

		label := truncate(r.f.Label, m.listWidth()-8)
		if i == m.cursor {
			label = stySelected.Render(label)
		}
		fmt.Fprintf(&b, "%s%s %s %s\n",
			cursor, box, severityStyle(r.f.Severity).Render(severityMark(r.f.Severity)), label)
	}
	if len(m.rows) == 0 {
		b.WriteString("\n  " + styOK.Render("Nothing hidden found in this file."))
		b.WriteString("\n\n  " + styFaint.Render("Press ? to see what that does and does not rule out."))
	}
	return b.String()
}

func (m Model) viewSaved() string {
	v := m.saved
	var b strings.Builder
	b.WriteString("\n\n")
	if v.OK() {
		b.WriteString("  " + styOK.Render("✓ clean copy written and verified"))
	} else {
		b.WriteString("  " + styAlarm.Render("✗ VERIFICATION FAILED"))
	}
	b.WriteString("\n\n  " + styPath.Render(v.Path) + "\n\n")
	b.WriteString("  " + styFaint.Render(fmt.Sprintf("%d finding(s) removed", v.Removed)) + "\n")

	// The verification line is the whole point of this screen: the file that was
	// written has been read back off disk and scanned again.
	if v.OK() {
		b.WriteString("  " + styFaint.Render("re-read from disk and re-scanned: none of them came back") + "\n")
	} else {
		b.WriteString("  " + styAlarm.Render(fmt.Sprintf(
			"%d selected finding(s) are still present in the written file", len(v.Leaked))) + "\n")
	}
	if len(v.Remaining) > 0 {
		b.WriteString("\n  " + styWarn.Render(fmt.Sprintf(
			"%d finding(s) left in place, as chosen:", len(v.Remaining))) + "\n")
		for _, f := range v.Remaining {
			b.WriteString("    " + styFaint.Render("· "+f.Label) + "\n")
		}
	}
	b.WriteString("\n  " + styFaint.Render("the original is untouched") + "\n")
	b.WriteString("\n" + styHelp.Render("  any key to go back to the findings · q to quit") + "\n")
	return b.String()
}

// ---------------------------------------------------------------------------
// detail rendering
// ---------------------------------------------------------------------------

func renderDetail(f finding.Finding, width int) string {
	var b strings.Builder

	// The label is wrapped rather than clipped: a finding whose label carries the
	// answer — which generator, which source type — should not lose it to the
	// panel edge.
	b.WriteString(styTitle.Render(wrap(f.Label, width)))
	b.WriteString("\n")
	b.WriteString(severityStyle(f.Severity).Render(strings.ToUpper(f.Severity.String())))
	b.WriteString(styFaint.Render(fmt.Sprintf("  ·  %s  ·  found by %s", f.Category, f.Detector)))
	b.WriteString("\n\n")

	b.WriteString(wrap(f.Why, width))
	b.WriteString("\n\n")

	switch d := f.Detail.(type) {
	case finding.Decoded:
		b.WriteString(styTitle.Render("What it says"))
		b.WriteString("\n")
		b.WriteString(styFaint.Render("encoded as " + d.Scheme))
		b.WriteString("\n\n")
		if d.Printable {
			b.WriteString(styPayload.Render(wrap(d.Text, width)))
		} else {
			b.WriteString(styPayload.Render(fmt.Sprintf("%d bytes of binary", len(d.Bytes))))
			b.WriteString("\n")
			b.WriteString(styFaint.Render(hexPreview(d.Bytes, 64)))
		}
		b.WriteString("\n")

	case finding.Runes:
		if d.Context != "" {
			b.WriteString(styTitle.Render("In context"))
			b.WriteString("\n")
			b.WriteString(styFaint.Render("invisible characters shown as ⟨…⟩"))
			b.WriteString("\n\n")
			b.WriteString(highlight(d.Context, width))
			b.WriteString("\n\n")
		}
		b.WriteString(styTitle.Render("Codepoints"))
		b.WriteString("\n")
		for i, name := range d.Names {
			if i >= 12 {
				b.WriteString(styFaint.Render(fmt.Sprintf("  … and %d more", len(d.Names)-12)))
				b.WriteString("\n")
				break
			}
			b.WriteString(styFaint.Render("  " + name))
			b.WriteString("\n")
		}

	case finding.Table:
		b.WriteString(styTitle.Render(strings.ToUpper(d.Source)))
		b.WriteString("\n\n")
		for _, kv := range d.Rows {
			// Values wrap under their key rather than running off the edge of the
			// panel. A Content Credential's rows are sentences — "matches: the
			// file still hashes to what was signed" — and a row cut mid-clause is
			// the one place in this viewer where the answer was on screen and
			// unreadable.
			const indent = "  "
			key := lipgloss.Width(kv.Key) + 2 // the key, its colon and a space
			for i, line := range strings.Split(wrap(kv.Value, width-key-len(indent)), "\n") {
				if kv.Sensitive {
					line = styWarn.Render(line)
				}
				if i == 0 {
					b.WriteString(indent + styFaint.Render(kv.Key+": ") + line + "\n")
					continue
				}
				b.WriteString(indent + strings.Repeat(" ", key) + line + "\n")
			}
		}

	case finding.Blob:
		b.WriteString(styTitle.Render("Bytes"))
		b.WriteString("\n\n")
		b.WriteString(styFaint.Render(hexPreview(d.Preview, 96)))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString(styRule.Render(strings.Repeat("─", maxInt(10, minInt(width, 40)))))
	b.WriteString("\n")
	b.WriteString(styFaint.Render(fmt.Sprintf("at byte %d, %d byte(s) long", f.Span.Offset, f.Span.Length)))
	b.WriteString("\n")
	if f.Removable {
		what := "deleted"
		if f.Replacement != nil {
			what = fmt.Sprintf("replaced with %q", string(f.Replacement))
		}
		b.WriteString(styOK.Render("can be removed — will be " + what))
	} else {
		b.WriteString(styWarn.Render("shown, but not removed"))
	}
	b.WriteString("\n")
	return b.String()
}

// highlight renders text with invisible characters made visible and marked, so
// the eye lands on them.
//
// Line width is measured on the plain stand-in, never on the styled one: a styled
// piece carries colour escapes that occupy no columns, and counting those as width
// wraps the pane to a third of its size.
func highlight(s string, width int) string {
	if width < 8 {
		width = 8
	}
	var b strings.Builder
	col := 0
	for _, r := range s {
		plain := report.Visible(string(r))
		w := len([]rune(plain))

		if col+w > width {
			b.WriteString("\n")
			col = 0
		}
		if plain != string(r) {
			b.WriteString(styHiddenChar.Render(plain))
		} else {
			b.WriteString(plain)
		}
		col += w

		// A newline stand-in is where the original text broke; break here too, so
		// the context reads with the same shape as the file.
		if r == '\n' {
			b.WriteString("\n")
			col = 0
		}
	}
	return b.String()
}

func hexPreview(b []byte, max int) string {
	if len(b) > max {
		b = b[:max]
	}
	var sb strings.Builder
	for i, x := range b {
		if i > 0 && i%16 == 0 {
			sb.WriteString("\n")
		}
		fmt.Fprintf(&sb, "%02x ", x)
	}
	return sb.String()
}

// wrap folds text to a column width, measuring what a terminal will actually
// draw rather than counting characters.
//
// Two things it has to get right, both of which it used not to. A character is
// not a column: CJK and emoji occupy two, so counting runes overflows the panel
// by up to a factor of two on exactly the text this tool exists to look at. And
// a word longer than the line has to be broken rather than emitted whole — a
// manifest URL, a document ID, a hash — because a line the panel cannot hold is
// a line the panel silently cuts, and the cut lands wherever it lands.
func wrap(s string, width int) string {
	if width < 12 {
		width = 12
	}
	var out []string
	for _, para := range strings.Split(s, "\n") {
		line := ""
		for _, word := range strings.Fields(para) {
			// A word that cannot fit on a line of its own is broken up first,
			// and its pieces are lines rather than words: joining them with a
			// space would insert a space that is not in the text.
			if lipgloss.Width(word) > width {
				if line != "" {
					out = append(out, line)
				}
				pieces := breakWord(word, width)
				out = append(out, pieces[:len(pieces)-1]...)
				line = pieces[len(pieces)-1]
				continue
			}
			switch {
			case line == "":
				line = word
			case lipgloss.Width(line)+1+lipgloss.Width(word) > width:
				out = append(out, line)
				line = word
			default:
				line += " " + word
			}
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// breakWord splits a word into pieces that each fit the width. Every piece is at
// least one character, so a width narrower than a single wide character still
// terminates — it overflows by one column rather than looping forever.
func breakWord(word string, width int) []string {
	var pieces []string
	current := ""
	for _, r := range word {
		if current != "" && lipgloss.Width(current)+lipgloss.Width(string(r)) > width {
			pieces = append(pieces, current)
			current = ""
		}
		current += string(r)
	}
	return append(pieces, current)
}

// truncate cuts a string to fit n columns, ending in an ellipsis when it had to
// cut. Columns rather than characters, for the same reason wrap counts them: a
// list of findings about CJK text was overflowing its pane by up to double,
// pushing the detail panel off the side of the terminal.
func truncate(s string, n int) string {
	if n < 4 {
		n = 4
	}
	if lipgloss.Width(s) <= n {
		return s
	}
	out := ""
	for _, r := range s {
		if lipgloss.Width(out)+lipgloss.Width(string(r))+1 > n {
			break
		}
		out += string(r)
	}
	return out + "…"
}

func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f kB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Run starts the viewer.
func Run(path string) error {
	m, err := New(path)
	if err != nil {
		return err
	}
	_, err = tea.NewProgram(m, tea.WithAltScreen()).Run()
	return err
}
