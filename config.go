package barndoor

import (
	"os"
	"strings"
)

// ProductionIssuer mirrors x-issuer on the spec's OAuth2 scheme. Hand-copied;
// config_test.go checks it against the spec.
const ProductionIssuer = "https://auth.barndoor.ai/realms/barndoor"

// Environment is a deployment to point the client at. Production needs no
// entry — the generated Configuration already carries its base URL.
type Environment struct {
	Issuer  string
	BaseURL string
}

var DEV = Environment{
	Issuer:  "https://auth.barndoordev.com/realms/barndoor",
	BaseURL: "https://platform.barndoordev.com",
}

var LOCAL = Environment{
	Issuer:  "https://auth.barndoorlocal.com/realms/barndoor",
	BaseURL: "https://mcp.barndoorlocal.com",
}

// EnvironmentFromEnv reads BARNDOOR_ENV ("dev" or "local") and
// BARNDOOR_API_URL, returning ok=false for production.
//
// Opt-in: the SDK never reads the environment by itself, so a variable set for
// something else cannot silently re-point a client at another cluster.
//
//	opts := []barndoor.Option{}
//	if env, ok := barndoor.EnvironmentFromEnv(); ok {
//		opts = append(opts, barndoor.WithEnvironment(env))
//	}
func EnvironmentFromEnv() (Environment, bool) {
	return environmentFrom(os.Getenv)
}

func environmentFrom(get func(string) string) (Environment, bool) {
	named := strings.ToLower(strings.TrimSpace(get("BARNDOOR_ENV")))
	base, known := map[string]Environment{"dev": DEV, "local": LOCAL}[named]

	url := strings.TrimSpace(get("BARNDOOR_API_URL"))
	if url == "" {
		return base, known
	}

	issuer := ProductionIssuer
	if known {
		issuer = base.Issuer
	}
	return Environment{Issuer: issuer, BaseURL: url}, true
}
