// Package agents knows where coding agents keep the files they read as
// instructions, and finds the ones present on this machine.
//
// It earns a place in augur because these files are the highest-value target for
// everything augur detects. An instruction file is read by a model on every
// session and by a human almost never — so a smuggled instruction in one is a
// prompt injection that persists, reloads itself, and has no reader to notice
// it. A zero-width payload in a README is a curiosity; the same payload in
// CLAUDE.md or a SKILL.md is a standing instruction.
//
// It sits in the surface layer: it knows about this machine and about other
// people's products, and nothing beneath it may learn either. Discovery only —
// scanning is the engine's job, and this package does not import it.
package agents

// Scope says whether a file applies everywhere or only to one checkout.
type Scope string

const (
	// Global files are read for every project on this machine.
	Global Scope = "global"
	// Project files travel with a repository, which means they arrive with a
	// clone and with every pull.
	Project Scope = "project"
)

// Source is one place an agent looks for instructions.
type Source struct {
	Scope Scope
	// Glob is relative to the home directory (Global) or the project root
	// (Project). It supports `*` within a path segment and `**` across segments.
	Glob string
	// Why says what reads this file and when. Shown beside a finding, because
	// "there is a hidden instruction in this file" only lands once you know the
	// file is loaded into a model's context automatically.
	Why string
}

// Agent is one tool, its installation markers, and the files it reads.
type Agent struct {
	ID   string
	Name string
	// Markers are paths relative to the home directory whose existence means the
	// agent is installed. Any one is enough.
	Markers []string
	Sources []Source
}

// Catalog is what augur knows about where agents keep instructions.
//
// Deliberately a list of specific paths rather than "every .md under the agent's
// directory". On the machine this was written for, ~/.claude holds 995 markdown
// files and ~/.codex holds 4077 — almost all of them session transcripts, plans
// and caches, which no model reads back as instructions. Scanning those would
// bury two real findings under four thousand irrelevant ones, and a report
// nobody can read is a report nobody reads.
func Catalog() []Agent {
	return []Agent{
		{
			ID:      "claude-code",
			Name:    "Claude Code",
			Markers: []string{".claude"},
			Sources: []Source{
				{Global, ".claude/CLAUDE.md", "loaded into every session on this machine"},
				{Global, ".claude/agents/*.md", "subagent definitions, loaded when the agent is invoked"},
				{Global, ".claude/commands/**/*.md", "slash commands, loaded when invoked"},
				{Global, ".claude/output-styles/*.md", "output styles, loaded when selected"},
				// A skill is a directory, not a file. Its SKILL.md routinely says
				// "see references/foo.md", and the model goes and reads it — so
				// scanning only SKILL.md covers barely a quarter of what a skill
				// actually puts into context. On the machine this was written for,
				// skill directories held 217 markdown files of which 59 were
				// SKILL.md.
				{Global, ".claude/skills/**/*.md", "skill instructions, loaded when the skill triggers"},
				// Installed plugins are third-party content that arrived over the
				// network, which makes them the least-reviewed instructions here.
				{Global, ".claude/plugins/**/skills/**/*.md", "installed plugin skill instructions"},
				// Scripts a skill ships are run on your behalf rather than read,
				// which makes a bidi override or a homoglyph in one a Trojan Source
				// attack with an agent pulling the trigger.
				{Global, ".claude/plugins/**/skills/**/*.sh", "script run by an installed plugin skill"},
				{Global, ".claude/plugins/**/skills/**/*.py", "script run by an installed plugin skill"},
				{Global, ".claude/plugins/**/commands/**/*.md", "installed plugin command"},
				{Global, ".claude/plugins/**/agents/*.md", "installed plugin subagent"},
				// Auto-memory is loaded into context at the start of every session
				// for its project, without anyone opening it.
				{Global, ".claude/projects/*/memory/*.md", "auto-memory, loaded into context each session"},
				// Nested, because a CLAUDE.md in a subdirectory is loaded when work
				// happens there — so the one that matters is often not at the root.
				{Project, "**/CLAUDE.md", "loaded for sessions working in its directory"},
				{Project, "**/CLAUDE.local.md", "loaded for sessions working in its directory"},
				{Project, ".claude/agents/*.md", "project subagent definitions"},
				{Project, ".claude/commands/**/*.md", "project slash commands"},
				{Project, ".claude/skills/**/*.md", "project skill instructions"},
				{Project, ".claude/output-styles/*.md", "project output styles"},
			},
		},
		{
			ID:      "codex",
			Name:    "Codex",
			Markers: []string{".codex"},
			Sources: []Source{
				{Global, ".codex/AGENTS.md", "loaded into every session on this machine"},
				{Global, ".codex/instructions.md", "loaded into every session on this machine"},
				{Global, ".codex/prompts/*.md", "saved prompts, loaded when invoked"},
			},
		},
		{
			ID:      "cursor",
			Name:    "Cursor",
			Markers: []string{".cursor"},
			Sources: []Source{
				{Global, ".cursor/rules/*.mdc", "global rules, loaded into every session"},
				{Project, ".cursorrules", "legacy project rules, loaded for this project"},
				{Project, ".cursor/rules/**/*.mdc", "project rules, loaded by glob match"},
			},
		},
		{
			ID:      "copilot",
			Name:    "GitHub Copilot",
			Markers: []string{".copilot", ".config/github-copilot"},
			Sources: []Source{
				{Project, ".github/copilot-instructions.md", "loaded for every request in this repository"},
				{Project, ".github/instructions/*.instructions.md", "path-scoped instructions"},
				{Project, ".github/prompts/*.prompt.md", "saved prompts, loaded when invoked"},
			},
		},
		{
			ID:      "opencode",
			Name:    "OpenCode",
			Markers: []string{".opencode", ".config/opencode"},
			Sources: []Source{
				{Global, ".config/opencode/AGENTS.md", "loaded into every session on this machine"},
				{Global, ".config/opencode/agent/*.md", "agent definitions"},
				{Global, ".config/opencode/command/*.md", "commands, loaded when invoked"},
				{Project, ".opencode/agent/*.md", "project agent definitions"},
				{Project, ".opencode/command/*.md", "project commands"},
			},
		},
		{
			ID:      "gemini-cli",
			Name:    "Gemini CLI",
			Markers: []string{".gemini"},
			Sources: []Source{
				{Global, ".gemini/GEMINI.md", "loaded into every session on this machine"},
				{Project, "GEMINI.md", "loaded for every session in this project"},
			},
		},
		{
			ID:      "windsurf",
			Name:    "Windsurf",
			Markers: []string{".codeium", ".windsurf"},
			Sources: []Source{
				{Global, ".codeium/windsurf/memories/global_rules.md", "global rules, loaded into every session"},
				{Project, ".windsurfrules", "legacy project rules"},
				{Project, ".windsurf/rules/*.md", "project rules"},
			},
		},
		{
			ID:      "cline",
			Name:    "Cline",
			Markers: []string{".cline", ".clinerules"},
			Sources: []Source{
				{Global, ".clinerules/*.md", "global rules"},
				{Project, ".clinerules", "project rules"},
				{Project, ".clinerules/**/*.md", "project rules"},
			},
		},
		{
			ID:      "continue",
			Name:    "Continue",
			Markers: []string{".continue"},
			Sources: []Source{
				{Global, ".continue/rules/*.md", "global rules"},
				{Project, ".continue/rules/*.md", "project rules"},
			},
		},
		{
			ID:      "junie",
			Name:    "Junie",
			Markers: []string{".junie"},
			Sources: []Source{
				{Project, ".junie/guidelines.md", "loaded for every session in this project"},
			},
		},
		{
			ID:      "aider",
			Name:    "Aider",
			Markers: []string{".aider.conf.yml", ".aider"},
			Sources: []Source{
				{Project, "CONVENTIONS.md", "loaded when added to the chat"},
			},
		},
		{
			ID:      "zed",
			Name:    "Zed",
			Markers: []string{".config/zed"},
			Sources: []Source{
				{Project, ".rules", "project rules"},
			},
		},
		{
			// AGENTS.md is a cross-tool convention rather than one product's file,
			// so it is listed once here instead of under every agent that reads it.
			// It has no installation marker: the file itself is the evidence.
			ID:      "agents-md",
			Name:    "AGENTS.md (cross-tool convention)",
			Markers: nil,
			Sources: []Source{
				{Project, "**/AGENTS.md", "read by several agents as instructions for its directory"},
				{Project, "**/AGENT.md", "read by several agents as instructions for its directory"},
			},
		},
	}
}
