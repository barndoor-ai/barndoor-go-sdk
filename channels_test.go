package barndoor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
)

// These tests run against a real httptest server, so the request that actually goes on
// the wire is what gets asserted. The emphasis is on what a caller can get wrong and
// what a refactor could silently change:
//
//   - the exact path and verb each method uses (a typo is a production 404 that the
//     compiler cannot catch);
//   - that Subscriptions is always sent, because the endpoint REPLACES rather than
//     merges and an omitted key would silently mean "unsubscribe from everything";
//   - that only supplied destination fields are forwarded (padding is a 422);
//   - that a failed channel test is a result, not an error return;
//   - that DELETE tolerates a real 204 with no body.

func channelJSON() map[string]any {
	url := "https://hooks.example.com/barndoor"
	return map[string]any{
		"id":                 "11111111-1111-1111-1111-111111111111",
		"type":               "webhook",
		"enabled":            true,
		"user_id":            nil,
		"email_address":      nil,
		"url":                url,
		"label":              nil,
		"slack_channel_id":   nil,
		"subscriptions":      []map[string]string{{"alert_type": "break_glass_used"}},
		"created_at":         "2026-08-26T00:00:00Z",
		"updated_at":         "2026-08-26T00:00:00Z",
		"has_signing_secret": true,
		"has_workflow_url":   false,
		"signing_secret":     nil,
	}
}

func TestListChannels_UnwrapsDataEnvelope(t *testing.T) {
	var gotPath, gotMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{channelJSON()}})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	channels, err := sdk.ListChannels(context.Background())
	if err != nil {
		t.Fatalf("ListChannels failed: %v", err)
	}
	if len(channels) != 1 {
		t.Fatalf("got %d channels, want 1", len(channels))
	}
	if channels[0].URL == nil || *channels[0].URL != "https://hooks.example.com/barndoor" {
		t.Errorf("URL not parsed: %+v", channels[0].URL)
	}
	if len(channels[0].Subscriptions) != 1 || channels[0].Subscriptions[0].AlertType != "break_glass_used" {
		t.Errorf("subscriptions not parsed: %+v", channels[0].Subscriptions)
	}
	if gotPath != "/api/notification/public/v1/channels" || gotMethod != "GET" {
		t.Errorf("got %s %s, want GET /api/notification/public/v1/channels", gotMethod, gotPath)
	}
}

func TestListChannels_EmptyAndMissingEnvelope(t *testing.T) {
	for name, body := range map[string]string{
		"empty data": `{"data": []}`,
		"no data":    `{}`,
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			sdk := newTestSDK(t, server)
			defer sdk.Close()

			channels, err := sdk.ListChannels(context.Background())
			if err != nil {
				t.Fatalf("ListChannels failed: %v", err)
			}
			if len(channels) != 0 {
				t.Errorf("got %d channels, want 0", len(channels))
			}
		})
	}
}

func TestListUserChannels_UsesUserPath(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		channel := channelJSON()
		channel["type"] = "in_app"
		channel["url"] = nil
		_ = json.NewEncoder(w).Encode(map[string]any{"data": []map[string]any{channel}})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	channels, err := sdk.ListUserChannels(context.Background())
	if err != nil {
		t.Fatalf("ListUserChannels failed: %v", err)
	}
	if channels[0].Type != ChannelTypeInApp {
		t.Errorf("got type %q, want in_app", channels[0].Type)
	}
	// Personal channels come from a distinct path, not a filter on the org list.
	if gotPath != "/api/notification/public/v1/channels/user" {
		t.Errorf("got path %q, want .../channels/user", gotPath)
	}
}

func TestGetChannelOptions(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"alert_types": []map[string]string{{
				"value":    "break_glass_used",
				"label":    "Break-glass used",
				"category": "access_control",
				"severity": "critical",
			}},
			"categories": []map[string]string{{"value": "access_control", "label": "Access control"}},
			"severities": []map[string]string{{"value": "critical", "label": "Critical"}},
		})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	options, err := sdk.GetChannelOptions(context.Background())
	if err != nil {
		t.Fatalf("GetChannelOptions failed: %v", err)
	}
	if len(options.AlertTypes) != 1 || options.AlertTypes[0].Severity != "critical" {
		t.Errorf("alert types not parsed: %+v", options.AlertTypes)
	}
	if gotPath != "/api/notification/public/v1/channels/options" {
		t.Errorf("got path %q, want .../channels/options", gotPath)
	}
}

// upsertProbe captures the request body a single upsert call sends.
func upsertProbe(t *testing.T, input UpsertChannelInput, response map[string]any) (map[string]any, string, string, *Channel) {
	t.Helper()

	var body map[string]any
	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Errorf("request body is not JSON: %v", err)
		}
		_ = json.NewEncoder(w).Encode(response)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	channel, err := sdk.UpsertChannel(context.Background(), input)
	if err != nil {
		t.Fatalf("UpsertChannel failed: %v", err)
	}
	return body, gotMethod, gotPath, channel
}

func TestUpsertChannel_CreateSendsNoIDAndRevealsSecret(t *testing.T) {
	response := channelJSON()
	response["signing_secret"] = "whsec_abc"

	body, method, path, channel := upsertProbe(t, UpsertChannelInput{
		Type:          ChannelTypeWebhook,
		URL:           "https://hooks.example.com/barndoor",
		Subscriptions: []string{"break_glass_used", "policy_changed"},
	}, response)

	if method != "PUT" || path != "/api/notification/public/v1/channels" {
		t.Errorf("got %s %s, want PUT /api/notification/public/v1/channels", method, path)
	}
	if _, present := body["id"]; present {
		t.Error("a create must not send an id")
	}
	subs, ok := body["subscriptions"].([]any)
	if !ok || len(subs) != 2 {
		t.Fatalf("subscriptions not sent as a 2-element list: %#v", body["subscriptions"])
	}
	// The one-time reveal must survive unmarshalling — losing it is unrecoverable
	// without a rotation.
	if channel.SigningSecret == nil || *channel.SigningSecret != "whsec_abc" {
		t.Errorf("signing secret lost: %+v", channel.SigningSecret)
	}
}

func TestUpsertChannel_EditByIDTrimsAndSendsID(t *testing.T) {
	disabled := false
	body, _, _, _ := upsertProbe(t, UpsertChannelInput{
		ChannelID: "  22222222-2222-2222-2222-222222222222  ",
		Type:      ChannelTypeWebhook,
		URL:       "https://hooks.example.com/barndoor",
		Enabled:   &disabled,
	}, channelJSON())

	if body["id"] != "22222222-2222-2222-2222-222222222222" {
		t.Errorf("id not sent trimmed: %#v", body["id"])
	}
	if body["enabled"] != false {
		t.Errorf("enabled=false not forwarded: %#v", body["enabled"])
	}
}

func TestUpsertChannel_AlwaysSendsSubscriptions(t *testing.T) {
	// Replace-not-merge: an absent key and an empty list are the same thing to this
	// endpoint, so the client sends it explicitly rather than relying on the server
	// defaulting a destructive operation.
	body, _, _, _ := upsertProbe(t, UpsertChannelInput{
		Type:         ChannelTypeEmail,
		EmailAddress: "ops@example.com",
	}, channelJSON())

	subs, present := body["subscriptions"]
	if !present {
		t.Fatal("subscriptions key must always be sent")
	}
	if list, ok := subs.([]any); !ok || len(list) != 0 {
		t.Errorf("want an empty list, got %#v", subs)
	}
}

func TestUpsertChannel_SendsOnlySuppliedDestinationFields(t *testing.T) {
	// Sending a field that does not belong to the type is a 422 server-side, so the
	// client must not pad the body with empty values for the other types' fields.
	body, _, _, _ := upsertProbe(t, UpsertChannelInput{
		Type:         ChannelTypeEmail,
		EmailAddress: "ops@example.com",
	}, channelJSON())

	got := make([]string, 0, len(body))
	for key := range body {
		got = append(got, key)
	}
	sort.Strings(got)
	want := []string{"email_address", "enabled", "subscriptions", "type"}
	if len(got) != len(want) {
		t.Fatalf("got keys %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got keys %v, want %v", got, want)
		}
	}
}

func TestUpsertChannel_DefaultsEnabledTrue(t *testing.T) {
	body, _, _, _ := upsertProbe(t, UpsertChannelInput{
		Type: ChannelTypeWebhook,
		URL:  "https://hooks.example.com/barndoor",
	}, channelJSON())

	if body["enabled"] != true {
		t.Errorf("enabled should default to true, got %#v", body["enabled"])
	}
}

func TestUpsertChannel_TeamsWorkflowURLForwarded(t *testing.T) {
	response := channelJSON()
	response["type"] = "teams"
	response["url"] = nil
	response["has_workflow_url"] = true

	body, _, _, channel := upsertProbe(t, UpsertChannelInput{
		Type:             ChannelTypeTeams,
		Label:            "Ops",
		TeamsWorkflowURL: "https://example.logic.azure.com/workflows/abc",
	}, response)

	if body["teams_workflow_url"] != "https://example.logic.azure.com/workflows/abc" {
		t.Errorf("teams workflow URL not forwarded: %#v", body["teams_workflow_url"])
	}
	// Write-only server-side: reads expose only the flag.
	if !channel.HasWorkflowURL {
		t.Error("has_workflow_url not parsed")
	}
}

func TestUpsertChannel_RejectsEmptyType(t *testing.T) {
	sdk := newTestSDK(t, httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("no request should be made when validation fails")
	})))
	defer sdk.Close()

	if _, err := sdk.UpsertChannel(context.Background(), UpsertChannelInput{Type: ""}); err == nil {
		t.Error("expected an error for an empty channel type")
	}
}

func TestUpsertChannel_RejectsBlankChannelID(t *testing.T) {
	sdk := newTestSDK(t, httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("no request should be made when validation fails")
	})))
	defer sdk.Close()

	_, err := sdk.UpsertChannel(context.Background(), UpsertChannelInput{
		Type:      ChannelTypeWebhook,
		ChannelID: "   ",
	})
	if err == nil {
		t.Error("expected an error for a blank channel ID")
	}
}

func TestDeleteChannel_ToleratesRealNoContentResponse(t *testing.T) {
	var gotPath, gotMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		// A real 204: no body at all. The client must not try to unmarshal it.
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	if err := sdk.DeleteChannel(context.Background(), "abc-123"); err != nil {
		t.Fatalf("DeleteChannel failed on a 204: %v", err)
	}
	if gotMethod != "DELETE" || gotPath != "/api/notification/public/v1/channels/abc-123" {
		t.Errorf("got %s %s, want DELETE .../channels/abc-123", gotMethod, gotPath)
	}
}

func TestDeleteChannel_RejectsBlankID(t *testing.T) {
	sdk := newTestSDK(t, httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("no request should be made when validation fails")
	})))
	defer sdk.Close()

	for _, id := range []string{"", "   "} {
		if err := sdk.DeleteChannel(context.Background(), id); err == nil {
			t.Errorf("expected an error for channel ID %q", id)
		}
	}
}

func TestDeleteChannel_SurfacesNotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"detail": "Channel not found"}`))
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	err := sdk.DeleteChannel(context.Background(), "nope")
	if err == nil {
		t.Fatal("expected an error for an unknown channel")
	}
	httpErr, ok := err.(*HTTPError)
	if !ok || httpErr.StatusCode != 404 {
		t.Errorf("want *HTTPError with status 404, got %T: %v", err, err)
	}
}

func TestRegenerateChannelSecret(t *testing.T) {
	var gotPath, gotMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.Path, r.Method
		_ = json.NewEncoder(w).Encode(map[string]string{"signing_secret": "whsec_rotated"})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	secret, err := sdk.RegenerateChannelSecret(context.Background(), "abc-123")
	if err != nil {
		t.Fatalf("RegenerateChannelSecret failed: %v", err)
	}
	if secret.SigningSecret != "whsec_rotated" {
		t.Errorf("got secret %q, want whsec_rotated", secret.SigningSecret)
	}
	if gotMethod != "POST" || gotPath != "/api/notification/public/v1/channels/abc-123/regenerate-secret" {
		t.Errorf("got %s %s, want POST .../regenerate-secret", gotMethod, gotPath)
	}
}

func TestTestChannel_Success(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "error": nil})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	result, err := sdk.TestChannel(context.Background(), "abc-123")
	if err != nil {
		t.Fatalf("TestChannel failed: %v", err)
	}
	if !result.OK {
		t.Error("want OK=true")
	}
	if gotPath != "/api/notification/public/v1/channels/abc-123/test" {
		t.Errorf("got path %q, want .../test", gotPath)
	}
}

func TestTestChannel_TransportFailureIsResultNotError(t *testing.T) {
	// A 200 with ok=false. Returning an error here would be wrong: the request
	// succeeded, only the downstream delivery failed.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": "connection refused"})
	}))
	defer server.Close()

	sdk := newTestSDK(t, server)
	defer sdk.Close()

	result, err := sdk.TestChannel(context.Background(), "abc-123")
	if err != nil {
		t.Fatalf("a transport failure must not be an error return: %v", err)
	}
	if result.OK {
		t.Error("want OK=false")
	}
	if result.Error == nil || *result.Error != "connection refused" {
		t.Errorf("error reason not parsed: %+v", result.Error)
	}
}
