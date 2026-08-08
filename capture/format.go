package capture

import (
	"fmt"
	"strings"
)

// HexDumpText renders a classic 16-bytes-per-line hex dump (offset, hex bytes,
// ASCII gutter), capped at maxBytes with a trailing "(N more bytes)" note.
// Preformatted server-side so clients render it verbatim in a <pre>-style box.
func HexDumpText(payload []byte, maxBytes int) string {
	if len(payload) == 0 {
		return "No payload data available"
	}
	display := len(payload)
	if maxBytes > 0 && display > maxBytes {
		display = maxBytes
	}
	var b strings.Builder
	for i := 0; i < display; i += 16 {
		fmt.Fprintf(&b, "%08x  ", i)
		for j := 0; j < 16; j++ {
			if i+j < display {
				fmt.Fprintf(&b, "%02x ", payload[i+j])
			} else {
				b.WriteString("   ")
			}
			if j == 7 {
				b.WriteByte(' ')
			}
		}
		b.WriteString(" |")
		for j := 0; j < 16 && i+j < display; j++ {
			c := payload[i+j]
			if c >= 32 && c <= 126 {
				b.WriteByte(c)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteString("|\n")
	}
	if display < len(payload) {
		fmt.Fprintf(&b, "... (%d more bytes)\n", len(payload)-display)
	}
	return b.String()
}

// ASCIIText renders payload as text: printable bytes kept, newline/CR/tab
// passed through, everything else a dot. Capped at maxBytes with a trailing
// "(N more bytes)" note.
func ASCIIText(payload []byte, maxBytes int) string {
	if len(payload) == 0 {
		return "No payload data available"
	}
	display := len(payload)
	if maxBytes > 0 && display > maxBytes {
		display = maxBytes
	}
	var b strings.Builder
	for i := 0; i < display; i++ {
		c := payload[i]
		switch {
		case c >= 32 && c <= 126:
			b.WriteByte(c)
		case c == '\n':
			b.WriteByte('\n')
		case c == '\r':
			b.WriteByte('\r')
		case c == '\t':
			b.WriteByte('\t')
		default:
			b.WriteByte('.')
		}
	}
	if display < len(payload) {
		fmt.Fprintf(&b, "\n\n... (%d more bytes)", len(payload)-display)
	}
	return b.String()
}
