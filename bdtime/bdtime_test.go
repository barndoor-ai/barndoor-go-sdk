package bdtime

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestUnmarshalAcceptsWhatTheServicesActuallySend(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  time.Time
	}{
		{
			// The shape registry-service returns; the reason this package exists.
			"registry, naive with microseconds",
			`"2026-05-08T17:26:31.084181"`,
			time.Date(2026, 5, 8, 17, 26, 31, 84181000, time.UTC),
		},
		{"naive, whole seconds", `"2026-05-08T17:26:31"`, time.Date(2026, 5, 8, 17, 26, 31, 0, time.UTC)},
		{"RFC 3339 with Z", `"2026-05-08T17:26:31Z"`, time.Date(2026, 5, 8, 17, 26, 31, 0, time.UTC)},
		{
			"RFC 3339 with fractional seconds and Z",
			`"2026-05-08T17:26:31.084181Z"`,
			time.Date(2026, 5, 8, 17, 26, 31, 84181000, time.UTC),
		},
		{"date only", `"2026-05-08"`, time.Date(2026, 5, 8, 0, 0, 0, 0, time.UTC)},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got Time
			if err := json.Unmarshal([]byte(tc.input), &got); err != nil {
				t.Fatalf("Unmarshal(%s): %v", tc.input, err)
			}
			if !got.Equal(tc.want) {
				t.Errorf("= %v, want %v", got.Time, tc.want)
			}
			if got.Location() != time.UTC {
				t.Errorf("location = %v, want UTC", got.Location())
			}
		})
	}
}

// Reinterpreting +01:00 as UTC would move every such timestamp by an hour.
func TestUnmarshalPreservesAnExplicitOffset(t *testing.T) {
	var got Time
	if err := json.Unmarshal([]byte(`"2026-05-08T17:26:31+01:00"`), &got); err != nil {
		t.Fatal(err)
	}
	want := time.Date(2026, 5, 8, 16, 26, 31, 0, time.UTC)
	if !got.Equal(want) {
		t.Errorf("= %v, want the same instant as %v", got.Time, want)
	}
}

// Otherwise the same payload decodes differently depending on where it runs.
func TestNaiveParsingDoesNotDependOnTheLocalZone(t *testing.T) {
	original := time.Local
	t.Cleanup(func() { time.Local = original })
	time.Local = time.FixedZone("UTC+9", 9*60*60)

	var got Time
	if err := json.Unmarshal([]byte(`"2026-05-08T17:26:31.084181"`), &got); err != nil {
		t.Fatal(err)
	}
	if want := time.Date(2026, 5, 8, 17, 26, 31, 84181000, time.UTC); !got.Equal(want) {
		t.Errorf("= %v, want %v — the local zone leaked into parsing", got.Time, want)
	}
}

func TestUnmarshalNullLeavesTheZeroValue(t *testing.T) {
	var got Time
	if err := json.Unmarshal([]byte(`null`), &got); err != nil {
		t.Fatal(err)
	}
	if !got.IsZero() {
		t.Errorf("= %v, want the zero time", got.Time)
	}
}

func TestUnmarshalRejectsWhatItCannotParse(t *testing.T) {
	for _, input := range []string{`"not a timestamp"`, `"08/05/2026"`, `12345`, `""`} {
		t.Run(input, func(t *testing.T) {
			var got Time
			err := json.Unmarshal([]byte(input), &got)
			if input == `""` {
				// Absent, not malformed.
				if err != nil || !got.IsZero() {
					t.Errorf("empty string: err=%v, value=%v", err, got.Time)
				}
				return
			}
			if err == nil {
				t.Fatalf("parsed %s as %v; want an error", input, got.Time)
			}
			if !strings.Contains(err.Error(), "bdtime") {
				t.Errorf("err = %q, want it to name this package so the source is obvious", err)
			}
		})
	}
}

// Whatever it accepts, what it sends carries an offset.
func TestMarshalAlwaysWritesAnOffset(t *testing.T) {
	var parsed Time
	if err := json.Unmarshal([]byte(`"2026-05-08T17:26:31.084181"`), &parsed); err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(parsed)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(out); got != `"2026-05-08T17:26:31.084181Z"` {
		t.Errorf("Marshal = %s, want an RFC 3339 value with a zone", got)
	}

	// A strict parser must be able to read it back.
	var strict time.Time
	if err := json.Unmarshal(out, &strict); err != nil {
		t.Errorf("a standard time.Time cannot read what we emit: %v", err)
	}
}

// The embedded time.Time must stay usable, or every caller has to unwrap.
func TestEmbeddedTimeMethodsWork(t *testing.T) {
	var got Time
	if err := json.Unmarshal([]byte(`"2026-05-08T17:26:31.084181"`), &got); err != nil {
		t.Fatal(err)
	}
	if got.Year() != 2026 || got.Month() != time.May || got.Day() != 8 {
		t.Errorf("embedded accessors wrong: %v", got.Time)
	}
	if !got.After(New(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)).Time) {
		t.Error("comparison against a standard time.Time failed")
	}
}

// A different code path from decoding the type alone.
func TestDecodesInsideAStruct(t *testing.T) {
	var row struct {
		Name      string `json:"name"`
		CreatedAt Time   `json:"created_at"`
	}
	body := `{"name":"Apollo","created_at":"2026-05-08T17:26:31.084181"}`
	if err := json.Unmarshal([]byte(body), &row); err != nil {
		t.Fatalf("this is the failure the whole package exists to prevent: %v", err)
	}
	if row.Name != "Apollo" || row.CreatedAt.Year() != 2026 {
		t.Errorf("decoded %+v", row)
	}
}
