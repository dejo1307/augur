package finding

// Detail is optional structured evidence attached to a finding. The set is closed
// and lives here rather than being `any`, for two reasons: renderers can switch on
// it exhaustively, and JSON output stays self-describing because every detail
// carries its own discriminator.
type Detail interface {
	// DetailKind names the concrete shape, so a JSON consumer can dispatch.
	DetailKind() string
}

// Runes is the evidence for a finding about specific codepoints: which ones, and
// what Unicode calls them. Codepoints and Names are parallel.
type Runes struct {
	Detail     string   `json:"detail_kind"`
	Codepoints []rune   `json:"codepoints"`
	Names      []string `json:"names"`
	// Context is the surrounding text with the offending runes still in it, so a
	// renderer can show them in place rather than in isolation. Byte offsets of
	// the run within Context are given by At.
	Context string `json:"context,omitempty"`
	At      []int  `json:"at,omitempty"`
}

func NewRunes(cps []rune, names []string) Runes {
	return Runes{Detail: "runes", Codepoints: cps, Names: names}
}

func (r Runes) DetailKind() string { return "runes" }

// Decoded is the evidence for a steganographic finding: a run of hidden characters
// that turned out to say something. Scheme names how it was encoded; Text is what
// it decoded to.
type Decoded struct {
	Detail string `json:"detail_kind"`
	Scheme string `json:"scheme"`
	Text   string `json:"text"`
	Bytes  []byte `json:"bytes,omitempty"`
	// Printable is false when the bytes decoded cleanly but are not readable text,
	// which is still a finding — it means something structured is in there.
	Printable bool `json:"printable"`
}

func NewDecoded(scheme, text string, raw []byte, printable bool) Decoded {
	return Decoded{Detail: "decoded", Scheme: scheme, Text: text, Bytes: raw, Printable: printable}
}

func (d Decoded) DetailKind() string { return "decoded" }

// KV is one row of a metadata table.
type KV struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	// Sensitive marks a row worth a second look on its own: coordinates, serial
	// numbers, personal names. The renderer highlights these.
	Sensitive bool `json:"sensitive,omitempty"`
}

// Table is the evidence for a metadata or provenance finding: the decoded contents
// of the block, so the user decides against what it actually says rather than
// against its name.
type Table struct {
	Detail string `json:"detail_kind"`
	Source string `json:"source"` // "exif", "xmp", "iptc", "png:tEXt", "c2pa"
	Rows   []KV   `json:"rows"`
	// Truncated is set when the block held more than the renderer was given.
	Truncated bool `json:"truncated,omitempty"`
}

func NewTable(source string, rows []KV) Table {
	return Table{Detail: "table", Source: source, Rows: rows}
}

func (t Table) DetailKind() string { return "table" }

// Blob is the evidence for a payload finding: bytes that should not be there. It
// carries a bounded preview rather than the whole thing.
type Blob struct {
	Detail  string `json:"detail_kind"`
	Size    int    `json:"size"`
	Preview []byte `json:"preview,omitempty"`
	// Sniffed names what the bytes look like, when they look like anything:
	// "zip archive", "jpeg", "utf-8 text". Empty when unrecognised.
	Sniffed string `json:"sniffed,omitempty"`
}

func NewBlob(size int, preview []byte, sniffed string) Blob {
	return Blob{Detail: "blob", Size: size, Preview: preview, Sniffed: sniffed}
}

func (b Blob) DetailKind() string { return "blob" }
