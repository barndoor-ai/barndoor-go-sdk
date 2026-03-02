package barndoor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// defaultTimeoutConfig
// ---------------------------------------------------------------------------

func TestDefaultTimeoutConfig(t *testing.T) {
	tc := defaultTimeoutConfig()
	if tc.read != 30*time.Second {
		t.Errorf("read = %v, want 30s", tc.read)
	}
	if tc.connect != 10*time.Second {
		t.Errorf("connect = %v, want 10s", tc.connect)
	}
}

// ---------------------------------------------------------------------------
// newHTTPClient
// ---------------------------------------------------------------------------

func TestNewHTTPClient(t *testing.T) {
	tc := timeoutConfig{read: 5 * time.Second, connect: 2 * time.Second}
	c := newHTTPClient(tc, 3)
	if c.maxRetries != 3 {
		t.Errorf("maxRetries = %d, want 3", c.maxRetries)
	}
	if c.closed {
		t.Error("new client should not be closed")
	}
}

// ---------------------------------------------------------------------------
// httpClient.request
// ---------------------------------------------------------------------------

func TestHTTPClient_Request_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	c := newHTTPClient(defaultTimeoutConfig(), 0)
	ctx := context.Background()

	resp, err := c.request(ctx, "GET", server.URL+"/test", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var data map[string]string
	if err := json.Unmarshal(resp, &data); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}
	if data["status"] != "ok" {
		t.Errorf("status = %q, want %q", data["status"], "ok")
	}
}

func TestHTTPClient_Request_WithJSONBody(t *testing.T) {
	var receivedBody map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedBody)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"ok":true}`)
	}))
	defer server.Close()

	c := newHTTPClient(defaultTimeoutConfig(), 0)
	ctx := context.Background()

	_, err := c.request(ctx, "POST", server.URL, &httpRequestOptions{
		JSON: map[string]string{"key": "value"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedBody["key"] != "value" {
		t.Errorf("body key = %q, want %q", receivedBody["key"], "value")
	}
}

func TestHTTPClient_Request_WithHeaders(t *testing.T) {
	var receivedAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	c := newHTTPClient(defaultTimeoutConfig(), 0)
	ctx := context.Background()

	_, err := c.request(ctx, "GET", server.URL, &httpRequestOptions{
		Headers: map[string]string{"Authorization": "Bearer test-token"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedAuth != "Bearer test-token" {
		t.Errorf("Authorization = %q", receivedAuth)
	}
}

func TestHTTPClient_Request_WithParams(t *testing.T) {
	var receivedQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedQuery = r.URL.Query().Get("page")
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	c := newHTTPClient(defaultTimeoutConfig(), 0)
	ctx := context.Background()

	_, err := c.request(ctx, "GET", server.URL, &httpRequestOptions{
		Params: map[string]string{"page": "2"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if receivedQuery != "2" {
		t.Errorf("page = %q, want %q", receivedQuery, "2")
	}
}

func TestHTTPClient_Request_4xxNoRetry(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprint(w, `{"error":"bad request"}`)
	}))
	defer server.Close()

	c := newHTTPClient(defaultTimeoutConfig(), 3)
	ctx := context.Background()

	_, err := c.request(ctx, "GET", server.URL, nil)
	if err == nil {
		t.Fatal("expected error for 400 response")
	}

	httpErr, ok := err.(*HTTPError)
	if !ok {
		t.Fatalf("expected HTTPError, got %T", err)
	}
	if httpErr.StatusCode != 400 {
		t.Errorf("StatusCode = %d, want 400", httpErr.StatusCode)
	}

	// 4xx should NOT retry
	if calls != 1 {
		t.Errorf("expected 1 call (no retry for 4xx), got %d", calls)
	}
}

func TestHTTPClient_Request_5xxRetryIdempotent(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprint(w, `{"error":"server error"}`)
			return
		}
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer server.Close()

	c := newHTTPClient(timeoutConfig{read: 5 * time.Second, connect: 2 * time.Second}, 3)
	ctx := context.Background()

	resp, err := c.request(ctx, "GET", server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error after retries: %v", err)
	}

	var data map[string]string
	json.Unmarshal(resp, &data)
	if data["status"] != "ok" {
		t.Errorf("expected ok response after retries")
	}
	if calls < 2 {
		t.Errorf("expected at least 2 calls (with retries), got %d", calls)
	}
}

func TestHTTPClient_Request_5xxNoRetryNonIdempotent(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":"server error"}`)
	}))
	defer server.Close()

	c := newHTTPClient(defaultTimeoutConfig(), 3)
	ctx := context.Background()

	_, err := c.request(ctx, "POST", server.URL, nil)
	if err == nil {
		t.Fatal("expected error for 500 on POST")
	}

	// POST is not idempotent, should NOT retry
	if calls != 1 {
		t.Errorf("expected 1 call (no retry for POST 5xx), got %d", calls)
	}
}

func TestHTTPClient_Request_ClosedClient(t *testing.T) {
	c := newHTTPClient(defaultTimeoutConfig(), 0)
	c.close()

	_, err := c.request(context.Background(), "GET", "http://localhost", nil)
	if err == nil {
		t.Fatal("expected error for closed client")
	}
	if !strings.Contains(err.Error(), "closed") {
		t.Errorf("expected 'closed' in error: %v", err)
	}
}

func TestHTTPClient_Request_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Second)
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	c := newHTTPClient(timeoutConfig{read: 30 * time.Second, connect: 10 * time.Second}, 0)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := c.request(ctx, "GET", server.URL, nil)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}

func TestHTTPClient_Request_UserAgent(t *testing.T) {
	var userAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userAgent = r.Header.Get("User-Agent")
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	c := newHTTPClient(defaultTimeoutConfig(), 0)
	c.request(context.Background(), "GET", server.URL, nil)

	expected := "barndoor-go-sdk/" + Version
	if userAgent != expected {
		t.Errorf("User-Agent = %q, want %q", userAgent, expected)
	}
}

// ---------------------------------------------------------------------------
// httpClient.buildURL
// ---------------------------------------------------------------------------

func TestBuildURL_NoParams(t *testing.T) {
	c := newHTTPClient(defaultTimeoutConfig(), 0)
	got, err := c.buildURL("https://example.com/api", nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "https://example.com/api" {
		t.Errorf("got %q", got)
	}
}

func TestBuildURL_WithParams(t *testing.T) {
	c := newHTTPClient(defaultTimeoutConfig(), 0)
	got, err := c.buildURL("https://example.com/api", map[string]string{"page": "2", "limit": "10"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "page=2") {
		t.Errorf("URL missing page param: %q", got)
	}
	if !strings.Contains(got, "limit=10") {
		t.Errorf("URL missing limit param: %q", got)
	}
}

func TestBuildURL_InvalidURL(t *testing.T) {
	c := newHTTPClient(defaultTimeoutConfig(), 0)
	_, err := c.buildURL("://invalid", map[string]string{"key": "val"})
	if err == nil {
		t.Fatal("expected error for invalid URL")
	}
}

// ---------------------------------------------------------------------------
// httpClient.close
// ---------------------------------------------------------------------------

func TestHTTPClient_Close(t *testing.T) {
	c := newHTTPClient(defaultTimeoutConfig(), 0)
	c.close()
	if !c.closed {
		t.Error("expected closed=true after close()")
	}
}

// ---------------------------------------------------------------------------
// httpClient.request — connection retry
// ---------------------------------------------------------------------------

func TestHTTPClient_Request_ConnectionRetry(t *testing.T) {
	// Use an unreachable address to trigger connection error
	c := newHTTPClient(timeoutConfig{read: 1 * time.Second, connect: 1 * time.Second}, 1)

	_, err := c.request(context.Background(), "GET", "http://127.0.0.1:1/test", nil)
	if err == nil {
		t.Fatal("expected error for unreachable host")
	}
}

func TestHTTPClient_Request_5xxExhaustsRetries(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, `{"error":"bad gateway"}`)
	}))
	defer server.Close()

	c := newHTTPClient(timeoutConfig{read: 5 * time.Second, connect: 2 * time.Second}, 2)
	_, err := c.request(context.Background(), "GET", server.URL, nil)
	if err == nil {
		t.Fatal("expected error after retries exhausted")
	}
	// Should have been called 3 times (initial + 2 retries)
	if calls != 3 {
		t.Errorf("expected 3 calls, got %d", calls)
	}
}

func TestHTTPClient_Request_EmptyParams(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	c := newHTTPClient(defaultTimeoutConfig(), 0)
	_, err := c.request(context.Background(), "GET", server.URL, &httpRequestOptions{
		Params: map[string]string{},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHTTPClient_Request_MethodUppercased(t *testing.T) {
	var receivedMethod string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedMethod = r.Method
		fmt.Fprint(w, `{}`)
	}))
	defer server.Close()

	c := newHTTPClient(defaultTimeoutConfig(), 0)
	_, err := c.request(context.Background(), "delete", server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if receivedMethod != "DELETE" {
		t.Errorf("method = %q, want DELETE", receivedMethod)
	}
}

func TestHTTPClient_Request_HeadIdempotent(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newHTTPClient(timeoutConfig{read: 5 * time.Second, connect: 2 * time.Second}, 2)
	_, err := c.request(context.Background(), "HEAD", server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// HEAD should be treated as idempotent and retried
	if calls < 2 {
		t.Errorf("expected retry for HEAD, got %d calls", calls)
	}
}

func TestHTTPClient_Request_JSONMarshalError(t *testing.T) {
	c := newHTTPClient(defaultTimeoutConfig(), 0)
	ctx := context.Background()

	// Channels cannot be marshaled to JSON
	_, err := c.request(ctx, "POST", "http://localhost", &httpRequestOptions{
		JSON: make(chan int),
	})
	if err == nil {
		t.Fatal("expected error for unmarshalable JSON body")
	}
	if !strings.Contains(err.Error(), "marshal") {
		t.Errorf("expected marshal error, got: %v", err)
	}
}

func TestHTTPClient_Request_OptionsIdempotent(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c := newHTTPClient(timeoutConfig{read: 5 * time.Second, connect: 2 * time.Second}, 2)
	_, err := c.request(context.Background(), "OPTIONS", server.URL, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls < 2 {
		t.Errorf("expected retry for OPTIONS, got %d calls", calls)
	}
}
