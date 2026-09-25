// Package bdtime holds a time.Time that also accepts a timestamp with no UTC
// offset.
//
// Some Barndoor endpoints serialise timestamps as "2026-05-08T17:26:31.084181".
// RFC 3339 requires an offset, so encoding/json refuses them and the WHOLE
// response fails — before this, every registry list endpoint returned a parse
// error while the server answered 200. The stored values are UTC
// (registry-service db/_base.py), so reading a naive one as UTC is recovering
// dropped information, not guessing.
//
// Wired in by gen-config.yaml's typeMappings, so regeneration cannot undo it.
package bdtime

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// Offset-bearing layouts first, so a value that carries a zone keeps it.
var layouts = []string{
	time.RFC3339Nano,                // 2026-05-08T17:26:31.084181Z / +01:00
	time.RFC3339,                    // second precision
	"2006-01-02T15:04:05.999999999", // naive, fractional — what registry sends
	"2006-01-02T15:04:05",           // naive, whole seconds
	"2006-01-02",                    // date only
}

// Time embeds time.Time, so Year, Before, Sub and Format all work unchanged.
type Time struct {
	time.Time
}

// New wraps a standard time.Time.
func New(t time.Time) Time { return Time{Time: t} }

// UnmarshalJSON accepts RFC 3339 and the same layout with the offset missing.
func (t *Time) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		return nil
	}

	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("bdtime: expected a JSON string, got %s", truncate(string(data)))
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}

	for _, layout := range layouts {
		// ParseInLocation, so a layout added later cannot pick up the local
		// zone and make decoding depend on where the process runs.
		if parsed, err := time.ParseInLocation(layout, raw, time.UTC); err == nil {
			t.Time = parsed
			return nil
		}
	}
	return fmt.Errorf("bdtime: cannot parse %q as a timestamp; tried %d layouts", raw, len(layouts))
}

// MarshalJSON always writes RFC 3339, so what this SDK sends conforms whatever
// it received.
func (t Time) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.Time.Format(time.RFC3339Nano))
}

// String renders RFC 3339, matching what the type marshals.
func (t Time) String() string { return t.Time.Format(time.RFC3339Nano) }

func truncate(s string) string {
	if len(s) > 40 {
		return s[:40] + "..."
	}
	return s
}
