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

// Kind says what happens to a file, which decides how a finding in it should be
// read — and how it should be printed.
type Kind string

const (
	// Instruction files are read into a model's context.
	Instruction Kind = "instruction"
	// Config files are read by the harness, and the commands in them are
	// EXECUTED. A bidi override or a homoglyph here is Trojan Source with an
	// agent pulling the trigger, which makes it a heavier finding than the same
	// characters in prose.
	//
	// Config files also routinely hold auth tokens, so the report never prints
	// surrounding context for one — it prints the JSON path instead, which is
	// both safer and more useful than a byte offset.
	Config Kind = "config"
	// Script files ship inside a skill and are run on your behalf.
	Script Kind = "script"
)

// Source is one place an agent looks for instructions.
type Source struct {
	Scope Scope
	Kind  Kind
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
				{Global, Instruction, ".claude/CLAUDE.md", "loaded into every session on this machine"},
				{Global, Instruction, ".claude/agents/*.md", "subagent definitions, loaded when the agent is invoked"},
				{Global, Instruction, ".claude/commands/**/*.md", "slash commands, loaded when invoked"},
				{Global, Instruction, ".claude/output-styles/*.md", "output styles, loaded when selected"},
				// A skill is a directory, not a file. Its SKILL.md routinely says
				// "see references/foo.md", and the model goes and reads it — so
				// scanning only SKILL.md covers barely a quarter of what a skill
				// actually puts into context. On the machine this was written for,
				// skill directories held 217 markdown files of which 59 were
				// SKILL.md.
				{Global, Instruction, ".claude/skills/**/*.md", "skill instructions, loaded when the skill triggers"},
				// Installed plugins are third-party content that arrived over the
				// network, which makes them the least-reviewed instructions here.
				{Global, Instruction, ".claude/plugins/**/skills/**/*.md", "installed plugin skill instructions"},
				// Scripts a skill ships are run on your behalf rather than read,
				// which makes a bidi override or a homoglyph in one a Trojan Source
				// attack with an agent pulling the trigger.
				{Global, Script, ".claude/plugins/**/skills/**/*.sh", "script run by an installed plugin skill"},
				{Global, Script, ".claude/plugins/**/skills/**/*.py", "script run by an installed plugin skill"},
				{Global, Instruction, ".claude/plugins/**/commands/**/*.md", "installed plugin command"},
				{Global, Instruction, ".claude/plugins/**/agents/*.md", "installed plugin subagent"},
				// Auto-memory is loaded into context at the start of every session
				// for its project, without anyone opening it.
				{Global, Instruction, ".claude/projects/*/memory/*.md", "auto-memory, loaded into context each session"},
				// Executed, not read: hook commands run on session events, and
				// mcpServers entries name a binary the harness launches. The
				// permissions allowlist is policy — a homoglyph in an entry makes
				// it silently stop matching the rule you think you wrote.
				{Global, Config, ".claude/settings.json", "hooks, permissions and MCP servers for every project"},
				{Global, Config, ".claude.json", "MCP servers launched for your projects"},
				{Project, Config, ".claude/settings.json", "hooks, permissions and MCP servers for this project"},
				{Project, Config, ".claude/settings.local.json", "hooks and permissions for this checkout"},
				{Project, Config, ".mcp.json", "MCP servers this project asks to launch"},
				// Nested, because a CLAUDE.md in a subdirectory is loaded when work
				// happens there — so the one that matters is often not at the root.
				{Project, Instruction, "**/CLAUDE.md", "loaded for sessions working in its directory"},
				{Project, Instruction, "**/CLAUDE.local.md", "loaded for sessions working in its directory"},
				{Project, Instruction, ".claude/agents/*.md", "project subagent definitions"},
				{Project, Instruction, ".claude/commands/**/*.md", "project slash commands"},
				{Project, Instruction, ".claude/skills/**/*.md", "project skill instructions"},
				{Project, Instruction, ".claude/output-styles/*.md", "project output styles"},
			},
		},
		{
			ID:      "codex",
			Name:    "Codex",
			Markers: []string{".codex"},
			Sources: []Source{
				{Global, Instruction, ".codex/AGENTS.md", "loaded into every session on this machine"},
				{Global, Instruction, ".codex/instructions.md", "loaded into every session on this machine"},
				{Global, Instruction, ".codex/prompts/*.md", "saved prompts, loaded when invoked"},
				{Global, Config, ".codex/config.toml", "MCP servers and settings"},
			},
		},
		{
			ID:      "cursor",
			Name:    "Cursor",
			Markers: []string{".cursor"},
			Sources: []Source{
				{Global, Instruction, ".cursor/rules/*.mdc", "global rules, loaded into every session"},
				{Global, Config, ".cursor/mcp.json", "MCP servers Cursor launches"},
				{Project, Config, ".cursor/mcp.json", "MCP servers this project asks Cursor to launch"},
				{Project, Instruction, ".cursorrules", "legacy project rules, loaded for this project"},
				{Project, Instruction, ".cursor/rules/**/*.mdc", "project rules, loaded by glob match"},
			},
		},
		{
			ID:      "copilot",
			Name:    "GitHub Copilot",
			Markers: []string{".copilot", ".config/github-copilot"},
			Sources: []Source{
				{Project, Instruction, ".github/copilot-instructions.md", "loaded for every request in this repository"},
				{Project, Instruction, ".github/instructions/*.instructions.md", "path-scoped instructions"},
				{Project, Instruction, ".github/prompts/*.prompt.md", "saved prompts, loaded when invoked"},
			},
		},
		{
			ID:      "opencode",
			Name:    "OpenCode",
			Markers: []string{".opencode", ".config/opencode"},
			Sources: []Source{
				{Global, Config, ".config/opencode/opencode.json", "MCP servers and agent config"},
				{Project, Config, "opencode.json", "MCP servers and agent config for this project"},
				{Global, Instruction, ".config/opencode/AGENTS.md", "loaded into every session on this machine"},
				{Global, Instruction, ".config/opencode/agent/*.md", "agent definitions"},
				{Global, Instruction, ".config/opencode/command/*.md", "commands, loaded when invoked"},
				{Project, Instruction, ".opencode/agent/*.md", "project agent definitions"},
				{Project, Instruction, ".opencode/command/*.md", "project commands"},
			},
		},
		{
			ID:      "gemini-cli",
			Name:    "Gemini CLI",
			Markers: []string{".gemini"},
			Sources: []Source{
				{Global, Instruction, ".gemini/GEMINI.md", "loaded into every session on this machine"},
				{Project, Instruction, "GEMINI.md", "loaded for every session in this project"},
			},
		},
		{
			ID:      "windsurf",
			Name:    "Windsurf",
			Markers: []string{".codeium", ".windsurf"},
			Sources: []Source{
				{Global, Instruction, ".codeium/windsurf/memories/global_rules.md", "global rules, loaded into every session"},
				{Project, Instruction, ".windsurfrules", "legacy project rules"},
				{Project, Instruction, ".windsurf/rules/*.md", "project rules"},
			},
		},
		{
			ID:      "cline",
			Name:    "Cline",
			Markers: []string{".cline", ".clinerules"},
			Sources: []Source{
				{Global, Instruction, ".clinerules/*.md", "global rules"},
				{Project, Instruction, ".clinerules", "project rules"},
				{Project, Instruction, ".clinerules/**/*.md", "project rules"},
			},
		},
		{
			ID:      "continue",
			Name:    "Continue",
			Markers: []string{".continue"},
			Sources: []Source{
				{Global, Instruction, ".continue/rules/*.md", "global rules"},
				{Global, Config, ".continue/config.json", "models and MCP servers"},
				{Project, Instruction, ".continue/rules/*.md", "project rules"},
			},
		},
		{
			ID:      "junie",
			Name:    "Junie",
			Markers: []string{".junie"},
			Sources: []Source{
				{Project, Instruction, ".junie/guidelines.md", "loaded for every session in this project"},
				{Global, Config, ".junie/settings.json", "agent settings"},
			},
		},
		{
			ID:      "aider",
			Name:    "Aider",
			Markers: []string{".aider.conf.yml", ".aider"},
			Sources: []Source{
				{Project, Instruction, "CONVENTIONS.md", "loaded when added to the chat"},
			},
		},
		{
			ID:      "zed",
			Name:    "Zed",
			Markers: []string{".config/zed"},
			Sources: []Source{
				{Project, Instruction, ".rules", "project rules"},
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
				{Project, Instruction, "**/AGENTS.md", "read by several agents as instructions for its directory"},
				{Project, Instruction, "**/AGENT.md", "read by several agents as instructions for its directory"},
			},
		},
	}
}
