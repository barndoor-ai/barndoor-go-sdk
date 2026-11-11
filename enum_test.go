package barndoor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/barndoor-ai/barndoor-go-sdk/v2/api"
)

// Adding an enum value is a minor API change, so a value newer than the SDK
// must not fail the response that carries it (templates/model_enum.mustache).
func TestUnknownEnumValueIsKept(t *testing.T) {
	var subs []api.ChannelSubscription
	body := `[{"alert_type":"added_after_this_sdk"},{"alert_type":"connection_broken"}]`
	if err := json.Unmarshal([]byte(body), &subs); err != nil {
		t.Fatalf("a response with an unknown enum value failed to parse: %v", err)
	}

	unknown := subs[0].GetAlertType()
	if unknown != "added_after_this_sdk" {
		t.Errorf("unknown value = %q, want it kept as sent", unknown)
	}

	if unknown.IsValid() {
		t.Error("IsValid() = true for a value this SDK does not list")
	}

	if subs[1].GetAlertType() != api.ALERTTYPE_CONNECTION_BROKEN {
		t.Errorf("known value = %q, want the listed constant", subs[1].GetAlertType())
	}

	out, err := json.Marshal(subs[0])
	if err != nil {
		t.Fatal(err)
	}

	if string(out) != `{"alert_type":"added_after_this_sdk"}` {
		t.Errorf("round trip = %s, want the value sent back unchanged", out)
	}

	// Building a request still checks against the known values.
	if _, err := api.NewAlertTypeFromValue("added_after_this_sdk"); err == nil {
		t.Error("NewAlertTypeFromValue accepted a value this SDK does not list")
	}
}

// The same for every generated enum. Go cannot list a package's types at run
// time, so this reads the generated source for the upstream error instead.
func TestNoGeneratedEnumRejectsAnUnknownValue(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("api", "model_*.go"))
	if err != nil {
		t.Fatal(err)
	}

	enums := 0
	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}

		text := string(src)
		if !strings.Contains(text, "EnumValues = []") {
			continue
		}

		enums++
		if strings.Contains(text, "is not a valid") {
			t.Errorf("%s: UnmarshalJSON rejects a value it does not list", file)
		}
	}

	if enums < 30 {
		t.Fatalf("found only %d generated enums; the discovery is broken", enums)
	}
}
