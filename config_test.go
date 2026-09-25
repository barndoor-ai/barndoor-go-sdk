package barndoor

import (
	"os"
	"regexp"
	"testing"
)

// The spec, wherever this package is checked out. A miss is a failure: a gate
// that skips when it cannot find its input never runs.
func specText(t *testing.T) string {
	t.Helper()
	for _, candidate := range []string{
		"../../docs/api/public-openapi.yaml", // monorepo
		"openapi.yaml",                       // SDK repo
	} {
		if b, err := os.ReadFile(candidate); err == nil {
			return string(b)
		}
	}
	t.Fatal("no spec found at ../../docs/api/public-openapi.yaml or openapi.yaml")
	return ""
}

// ProductionIssuer is hand-copied; this holds it honest. Matched textually
// because a test-only yaml dep would follow this module into every consumer's
// go.sum. A restructured spec matches nothing and fails, rather than passing.
func TestProductionIssuerMatchesTheSpec(t *testing.T) {
	matches := regexp.MustCompile(`(?m)^\s*x-issuer:\s*(\S+)\s*$`).FindAllStringSubmatch(specText(t), -1)
	if len(matches) != 1 {
		t.Fatalf("expected exactly one x-issuer in the spec, found %d", len(matches))
	}
	if got := matches[0][1]; got != ProductionIssuer {
		t.Errorf("ProductionIssuer = %q, spec declares %q", ProductionIssuer, got)
	}
}

// The production base URL comes from the spec; a second copy would drift.
func TestProductionBaseURLIsNotRestatedHere(t *testing.T) {
	for _, env := range []Environment{DEV, LOCAL} {
		if env.BaseURL == "https://platform.barndoor.ai" {
			t.Errorf("%+v restates the production base URL", env)
		}
	}
}

func TestEnvironmentFromEnv(t *testing.T) {
	cases := []struct {
		name  string
		vars  map[string]string
		want  Environment
		wantK bool
	}{
		{"unset means production", nil, Environment{}, false},
		{"dev", map[string]string{"BARNDOOR_ENV": "dev"}, DEV, true},
		{"case insensitive", map[string]string{"BARNDOOR_ENV": "DEV"}, DEV, true},
		{"surrounding space", map[string]string{"BARNDOOR_ENV": " local "}, LOCAL, true},
		{"unknown name means production", map[string]string{"BARNDOOR_ENV": "staging"}, Environment{}, false},
		{
			"url alone takes the production issuer",
			map[string]string{"BARNDOOR_API_URL": "https://example.test"},
			Environment{Issuer: ProductionIssuer, BaseURL: "https://example.test"},
			true,
		},
		{
			"url with a named environment keeps that issuer",
			map[string]string{"BARNDOOR_ENV": "dev", "BARNDOOR_API_URL": "https://example.test"},
			Environment{Issuer: DEV.Issuer, BaseURL: "https://example.test"},
			true,
		},
		{
			"an empty url is not an override",
			map[string]string{"BARNDOOR_ENV": "dev", "BARNDOOR_API_URL": "  "},
			DEV,
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := environmentFrom(func(k string) string { return tc.vars[k] })
			if ok != tc.wantK || got != tc.want {
				t.Errorf("environmentFrom(%v) = %+v, %v; want %+v, %v", tc.vars, got, ok, tc.want, tc.wantK)
			}
		})
	}
}

// The cases above take a lookup function, so without this the wiring could be
// wrong and they would all still pass.
func TestEnvironmentFromEnvReadsTheProcessEnvironment(t *testing.T) {
	t.Setenv("BARNDOOR_ENV", "local")
	t.Setenv("BARNDOOR_API_URL", "")

	got, ok := EnvironmentFromEnv()
	if !ok || got != LOCAL {
		t.Errorf("EnvironmentFromEnv() = %+v, %v; want %+v, true", got, ok, LOCAL)
	}
}
