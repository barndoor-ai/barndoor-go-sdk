package barndoor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/barndoor-ai/barndoor-go-sdk/v2/api"
)

func TestNewExposesEveryNamespace(t *testing.T) {
	client := New(StaticToken("k"))

	value := reflect.ValueOf(*client)
	for i := range value.NumField() {
		if value.Field(i).IsNil() {
			t.Errorf("%s is nil", value.Type().Field(i).Name)
		}
	}
}

// Adding a namespace to the spec must not leave it invisible to callers.
func TestEveryGeneratedServiceIsExposed(t *testing.T) {
	client := New(StaticToken("k"))

	exposed := map[string]bool{}
	value := reflect.ValueOf(*client)
	for i := range value.NumField() {
		exposed[value.Type().Field(i).Type.String()] = true
	}

	generated := reflect.ValueOf(*client.API)
	missing := 0
	for i := range generated.NumField() {
		field := generated.Type().Field(i)
		if !strings.HasSuffix(field.Name, "API") {
			continue
		}
		if !exposed[field.Type.String()] {
			t.Errorf("api.APIClient.%s (%s) is not exposed on Client", field.Name, field.Type)
			missing++
		}
	}
	if generated.NumField() == 0 {
		t.Fatal("found no fields on the generated APIClient; this test is asserting nothing")
	}
	t.Logf("checked %d generated fields, %d unexposed", generated.NumField(), missing)
}

// Attached by the transport, so no call site threads a context value.
func TestRequestsCarryTheToken(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Authorization")
		writeEmptyServerList(w)
	}))
	defer server.Close()

	client := New(StaticToken("bdai_key"), WithEnvironment(Environment{BaseURL: server.URL}))
	if _, _, err := client.Registry.ListMcpServers(context.Background()).Execute(); err != nil {
		t.Fatal(err)
	}

	if got != "Bearer bdai_key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer bdai_key")
	}
}

// A fresh token per request is what makes refresh work.
func TestEveryRequestAsksTheTokenSourceAgain(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		writeEmptyServerList(w)
	}))
	defer server.Close()

	client := New(&rotatingSource{}, WithEnvironment(Environment{BaseURL: server.URL}))
	for range 2 {
		if _, _, err := client.Registry.ListMcpServers(context.Background()).Execute(); err != nil {
			t.Fatal(err)
		}
	}

	if len(seen) != 2 {
		t.Fatalf("server saw %d requests, want 2", len(seen))
	}
	if seen[0] == seen[1] {
		t.Errorf("both requests carried %q; the token source is consulted once, not per request", seen[0])
	}
}

func TestWithEnvironmentReplacesTheServer(t *testing.T) {
	client := New(StaticToken("k"), WithEnvironment(DEV))
	url, err := client.Configuration.ServerURLWithContext(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if url != DEV.BaseURL {
		t.Errorf("server URL = %q, want %q", url, DEV.BaseURL)
	}
}

func TestDefaultsToTheSpecsProductionServer(t *testing.T) {
	client := New(StaticToken("k"))
	url, err := client.Configuration.ServerURLWithContext(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://platform.barndoor.ai" {
		t.Errorf("default server URL = %q, want the spec's production host", url)
	}
}

func TestWithHeaderIsSentOnEveryRequest(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("X-Trace")
		writeEmptyServerList(w)
	}))
	defer server.Close()

	client := New(StaticToken("k"),
		WithEnvironment(Environment{BaseURL: server.URL}),
		WithHeader("X-Trace", "abc"))
	if _, _, err := client.Registry.ListMcpServers(context.Background()).Execute(); err != nil {
		t.Fatal(err)
	}

	if got != "abc" {
		t.Errorf("X-Trace = %q, want abc", got)
	}
}

// Forgetting to wire retries fails invisibly: the client is just less resilient.
func TestRetriesAreOnByDefault(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		writeEmptyServerList(w)
	}))
	defer server.Close()

	client := New(StaticToken("k"),
		WithEnvironment(Environment{BaseURL: server.URL}),
		WithRetry(RetryOptions{Retries: 2, Backoff: 1}))
	_, resp, err := client.Registry.ListMcpServers(context.Background()).Execute()
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck
	if calls != 2 {
		t.Errorf("server saw %d requests, want 2 (the 503 was retried)", calls)
	}
}

// A client that consults its source once shows up as two identical headers.
// The smallest body ListMcpServers will deserialise. A short one fails inside
// the generated client, passing a transport assertion for the wrong reason.
func writeEmptyServerList(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"data":[],"pagination":{"page":1,"limit":10,"total":0,"pages":0,"previous_page":null,"next_page":null}}`))
}

type rotatingSource struct{ n int }

func (r *rotatingSource) Token() (*oauth2.Token, error) {
	r.n++
	return &oauth2.Token{AccessToken: fmt.Sprintf("token-%d", r.n), TokenType: "Bearer"}, nil
}

// Guards on generated OUTPUT. templateDir overrides whole files and a config key
// can stop being honoured, either silently — these are what notice.

// Without modelNameMappings the component enum is never generated and the
// parameter's anyOf wrapper takes its name.
func TestConnectionStatusEnumIsRenamed(t *testing.T) {
	var status api.ServerConnectionStatus
	if reflect.TypeOf(status).Kind() != reflect.String {
		t.Errorf("ServerConnectionStatus is %s, want a string enum", reflect.TypeOf(status).Kind())
	}
	if _, err := json.Marshal(api.SERVERCONNECTIONSTATUS_CONNECTED); err != nil {
		t.Errorf("the enum does not serialise: %v", err)
	}
}

// A miss is a failure, not a skip: an earlier version looked at a model with no
// such field and skipped, reporting green while checking nothing.
func TestServerConnectionStateIsTheEnum(t *testing.T) {
	carriers := []reflect.Type{
		reflect.TypeOf(api.ServerListResponse{}),
		reflect.TypeOf(api.ServerResponse{}),
	}
	for _, typ := range carriers {
		field, ok := typ.FieldByName("ConnectionStatus")
		if !ok {
			t.Errorf("%s has no ConnectionStatus field; the spec changed shape", typ)
			continue
		}
		if !strings.Contains(field.Type.String(), "ServerConnectionStatus") {
			t.Errorf("%s.ConnectionStatus is %s, want the renamed enum", typ, field.Type)
		}
	}
}

// The mapped value must be Go-cased: a snake_case one compiles and yields an
// unexported field that encoding/json silently drops.
func TestSigningSecretPresentIsExportedAndKeepsItsWireName(t *testing.T) {
	field, ok := reflect.TypeOf(api.ChannelResponse{}).FieldByName("SigningSecretPresent")
	if !ok {
		t.Fatal("ChannelResponse has no SigningSecretPresent field; check nameMappings in gen-config.yaml")
	}
	if !field.IsExported() {
		t.Error("SigningSecretPresent is unexported, so encoding/json will drop it")
	}
	if got := field.Tag.Get("json"); got != "has_signing_secret,omitempty" {
		t.Errorf(`json tag = %q, want "has_signing_secret,omitempty" — the wire name must not change`, got)
	}

	// A tag can be right while the hand-written marshaller ignores the field.
	yes := true
	encoded, err := json.Marshal(api.ChannelResponse{SigningSecretPresent: &yes})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"has_signing_secret":true`) {
		t.Errorf("marshalled as %s, want has_signing_secret present", encoded)
	}
}

// `ArrayOf*string` is a parse error rather than a test failure, so assert the
// field survives under a legal name.
func TestAnyOfMemberNamesAreLegalIdentifiers(t *testing.T) {
	typ := reflect.TypeOf(api.ConnectionStatus{})
	if typ.NumField() == 0 {
		t.Fatal("ConnectionStatus has no fields; this test is asserting nothing")
	}
	for i := range typ.NumField() {
		name := typ.Field(i).Name
		if strings.ContainsAny(name, "*[]") {
			t.Errorf("field %q is not a legal Go identifier", name)
		}
	}
}

// Go maps `format: uuid` to string on both sides, so list->get chains natively.
// This notices if a generator upgrade starts minting a UUID type.
func TestIdsAndPathParametersAreTheSameType(t *testing.T) {
	field, ok := reflect.TypeOf(api.PolicySummary{}).FieldByName("Id")
	if !ok {
		t.Fatal("PolicySummary has no Id field; the spec changed shape")
	}
	if field.Type.Kind() != reflect.String {
		t.Errorf("PolicySummary.Id is %s; a non-string id no longer feeds GetPolicy(ctx, policyId string)", field.Type)
	}
}

// typeMappings puts bdtime.Time on the models. Drop it and the package still
// compiles, and every registry list endpoint fails against the real service.
func TestGeneratedModelsUseTheLenientTimeType(t *testing.T) {
	for _, tc := range []struct {
		model reflect.Type
		field string
	}{
		{reflect.TypeOf(api.ServerListResponse{}), "CreatedAt"},
		{reflect.TypeOf(api.ServerListResponse{}), "UpdatedAt"},
		{reflect.TypeOf(api.ConnectionRead{}), "CreatedAt"},
		{reflect.TypeOf(api.ChannelResponse{}), "CreatedAt"},
	} {
		field, ok := tc.model.FieldByName(tc.field)
		if !ok {
			t.Errorf("%s has no %s field; the spec changed shape", tc.model, tc.field)
			continue
		}
		if got := field.Type.String(); got != "bdtime.Time" {
			t.Errorf("%s.%s is %s, want bdtime.Time — check typeMappings in gen-config.yaml",
				tc.model, tc.field, got)
		}
	}
}

// The mapping does not reach utils.go; templates/utils.mustache closes that gap.
func TestNullableTimeUsesTheLenientTimeType(t *testing.T) {
	got := reflect.TypeOf(api.NullableTime{}.Get()).String()
	if got != "*bdtime.Time" {
		t.Errorf("NullableTime.Get() returns %s, want *bdtime.Time — check templates/utils.mustache", got)
	}
}

// This payload shape returned 200 from DEV and failed to parse. Values are
// fictional; only the timestamp format is copied from the real response.
func TestARegistryPayloadWithNaiveTimestampsDeserialises(t *testing.T) {
	body := `{
	  "id": "11111111-1111-1111-1111-111111111111",
	  "mcp_server_id": "22222222-2222-2222-2222-222222222222",
	  "status": "connected",
	  "created_at": "2026-05-08T17:26:31.084181",
	  "connected_at": "2026-05-08T17:26:32.000000",
	  "last_accessed_at": null
	}`

	var row api.ConnectionRead
	if err := json.Unmarshal([]byte(body), &row); err != nil {
		t.Fatalf("a naive timestamp still breaks deserialisation: %v", err)
	}

	if row.CreatedAt.Year() != 2026 || row.CreatedAt.Month() != time.May || row.CreatedAt.Day() != 8 {
		t.Errorf("CreatedAt = %v", row.CreatedAt)
	}
	if row.CreatedAt.Location() != time.UTC {
		t.Errorf("CreatedAt location = %v, want UTC", row.CreatedAt.Location())
	}
	// Travels through the vendored NullableTime.
	if !row.ConnectedAt.IsSet() || row.ConnectedAt.Get() == nil {
		t.Fatal("ConnectedAt did not decode through NullableTime")
	}
	if row.ConnectedAt.Get().Second() != 32 {
		t.Errorf("ConnectedAt = %v", row.ConnectedAt.Get())
	}
	if row.LastAccessedAt.Get() != nil {
		t.Errorf("LastAccessedAt = %v, want nil for an explicit JSON null", row.LastAccessedAt.Get())
	}
}

// anyOf query parameters. The generator had no encoding for the struct it mints
// and sent the literal "api.ConnectionStatus value". These assert on the wire —
// the type compiling says nothing about what reaches the server.

func TestAnyOfQueryParameterIsEncodedAsItsMember(t *testing.T) {
	connected, available := "connected", "available"
	list := []*string{&connected, &available}

	cases := []struct {
		name  string
		param api.ConnectionStatus
		want  []string
	}{
		{"single string", api.ConnectionStatus{String: &connected}, []string{"connected"}},
		{
			"array expands to repeated parameters", // ?x=a&x=b, per the spec
			api.ConnectionStatus{ArrayOfstring: &list},
			[]string{"connected", "available"},
		},
		{"empty wrapper sends nothing", api.ConnectionStatus{}, nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var query url.Values
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				query = r.URL.Query()
				writeEmptyServerList(w)
			}))
			defer server.Close()

			client := New(StaticToken("k"), WithEnvironment(Environment{BaseURL: server.URL}))
			if _, _, err := client.Registry.ListMcpServers(context.Background()).
				ConnectionStatus(tc.param).Execute(); err != nil {
				t.Fatal(err)
			}

			got := query["connection_status"]
			if len(got) != len(tc.want) {
				t.Fatalf("connection_status = %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("connection_status[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// The fallback sends a plausible string, so it fails at the server rather than
// here — assert the shape, not just that something was sent.
func TestAnyOfQueryParameterNeverSendsTheTypeName(t *testing.T) {
	var raw string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw = r.URL.RawQuery
		writeEmptyServerList(w)
	}))
	defer server.Close()

	connected := "connected"
	client := New(StaticToken("k"), WithEnvironment(Environment{BaseURL: server.URL}))
	if _, _, err := client.Registry.ListMcpServers(context.Background()).
		ConnectionStatus(api.ConnectionStatus{String: &connected}).Execute(); err != nil {
		t.Fatal(err)
	}

	if strings.Contains(raw, "ConnectionStatus") || strings.Contains(raw, "+value") {
		t.Errorf("query carries the Go type name instead of the value: %s", raw)
	}
	if !strings.Contains(raw, "connection_status=connected") {
		t.Errorf("query = %s, want connection_status=connected", raw)
	}
}
