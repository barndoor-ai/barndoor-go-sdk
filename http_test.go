package barndoor

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Scripted statuses, recording what it was asked, so tests assert on attempts
// rather than elapsed time.
type countingTransport struct {
	statuses []int
	err      error

	calls   atomic.Int32
	bodies  []string
	closed  atomic.Int32
	headers []http.Header
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	n := int(c.calls.Add(1)) - 1

	body := ""
	if req.Body != nil {
		b, _ := io.ReadAll(req.Body)
		body = string(b)
	}
	c.bodies = append(c.bodies, body)
	c.headers = append(c.headers, req.Header.Clone())

	if c.err != nil {
		return nil, c.err
	}
	status := c.statuses[len(c.statuses)-1]
	if n < len(c.statuses) {
		status = c.statuses[n]
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{},
		Body:       &countingBody{Reader: strings.NewReader("body"), closed: &c.closed},
		Request:    req,
	}, nil
}

type countingBody struct {
	io.Reader
	closed *atomic.Int32
}

func (b *countingBody) Close() error {
	b.closed.Add(1)
	return nil
}

func fastRetry(retries int) RetryOptions {
	return RetryOptions{Retries: retries, Backoff: time.Microsecond}
}

func do(t *testing.T, next http.RoundTripper, opts RetryOptions, method, body string) (*http.Response, error) {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, "https://example.test/x", reader)
	if err != nil {
		t.Fatal(err)
	}
	return (&RetryTransport{Next: next, Options: opts}).RoundTrip(req)
}

func TestRetriesIdempotentRequestsOnRetryableStatuses(t *testing.T) {
	for _, status := range []int{500, 502, 503, 504, 429} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			next := &countingTransport{statuses: []int{status, 200}}
			resp, err := do(t, next, fastRetry(3), http.MethodGet, "")
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 200 {
				t.Errorf("status = %d, want 200", resp.StatusCode)
			}
			if got := next.calls.Load(); got != 2 {
				t.Errorf("attempts = %d, want 2", got)
			}
		})
	}
}

// The server understood these and will refuse them identically.
func TestDoesNotRetryStatusesThatCannotChange(t *testing.T) {
	for _, status := range []int{501, 505, 400, 401, 404, 422} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			next := &countingTransport{statuses: []int{status}}
			if _, err := do(t, next, fastRetry(3), http.MethodGet, ""); err != nil {
				t.Fatal(err)
			}
			if got := next.calls.Load(); got != 1 {
				t.Errorf("attempts = %d, want 1", got)
			}
		})
	}
}

// A 502 does not say whether a POST reached the application.
func TestDoesNotRetryNonIdempotentMethods(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPatch} {
		t.Run(method, func(t *testing.T) {
			next := &countingTransport{statuses: []int{503, 200}}
			resp, err := do(t, next, fastRetry(3), method, `{"a":1}`)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != 503 {
				t.Errorf("status = %d, want the 503 surfaced", resp.StatusCode)
			}
			if got := next.calls.Load(); got != 1 {
				t.Errorf("attempts = %d, want 1", got)
			}
		})
	}
}

// Without replay the second attempt sends an empty body.
func TestReplaysTheBodyOnRetry(t *testing.T) {
	next := &countingTransport{statuses: []int{503, 200}}
	if _, err := do(t, next, fastRetry(3), http.MethodPut, `{"a":1}`); err != nil {
		t.Fatal(err)
	}
	if len(next.bodies) != 2 {
		t.Fatalf("attempts = %d, want 2", len(next.bodies))
	}
	if next.bodies[0] != next.bodies[1] {
		t.Errorf("retry sent %q, first attempt sent %q", next.bodies[1], next.bodies[0])
	}
}

// A body net/http cannot rewind was consumed by the first attempt.
func TestDoesNotRetryAnUnrewindableBody(t *testing.T) {
	next := &countingTransport{statuses: []int{503, 200}}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, "https://example.test/x",
		io.NopCloser(strings.NewReader("stream")))
	if err != nil {
		t.Fatal(err)
	}
	if req.GetBody != nil {
		t.Fatal("expected an opaque reader to leave GetBody nil; this test no longer tests anything")
	}
	if _, err := (&RetryTransport{Next: next, Options: fastRetry(3)}).RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if got := next.calls.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
}

func TestGivesUpAfterTheConfiguredAttempts(t *testing.T) {
	next := &countingTransport{statuses: []int{503}}
	resp, err := do(t, next, fastRetry(2), http.MethodGet, "")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 503 {
		t.Errorf("status = %d, want the last 503 returned", resp.StatusCode)
	}
	if got := next.calls.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3 (the first plus two retries)", got)
	}
}

func TestZeroRetriesDisablesRetrying(t *testing.T) {
	next := &countingTransport{statuses: []int{503, 200}}
	if _, err := do(t, next, RetryOptions{}, http.MethodGet, ""); err != nil {
		t.Fatal(err)
	}
	if got := next.calls.Load(); got != 1 {
		t.Errorf("attempts = %d, want 1", got)
	}
}

// An unclosed discarded body keeps its connection out of the pool.
func TestClosesTheBodyOfARetriedResponse(t *testing.T) {
	next := &countingTransport{statuses: []int{503, 503, 200}}
	if _, err := do(t, next, fastRetry(3), http.MethodGet, ""); err != nil {
		t.Fatal(err)
	}
	if got := next.closed.Load(); got != 2 {
		t.Errorf("closed %d discarded bodies, want 2", got)
	}
}

func TestRetriesTransportErrors(t *testing.T) {
	sentinel := errors.New("dial tcp: connection refused")
	next := &countingTransport{err: sentinel}
	_, err := do(t, next, fastRetry(2), http.MethodGet, "")
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want %v", err, sentinel)
	}
	if got := next.calls.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

// Seconds or an HTTP date; both must beat the computed backoff.
func TestHonoursRetryAfter(t *testing.T) {
	for _, header := range []string{"0.05", time.Now().Add(50 * time.Millisecond).UTC().Format(http.TimeFormat)} {
		t.Run(header, func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if calls.Add(1) == 1 {
					w.Header().Set("Retry-After", header)
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			// Backoff far longer than the header, so ignoring it shows up.
			opts := RetryOptions{Retries: 2, Backoff: time.Minute, Timeout: 10 * time.Second}
			client := NewHTTPClient(opts, nil)

			start := time.Now()
			resp, err := client.Get(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close() //nolint:errcheck
			if resp.StatusCode != http.StatusOK {
				t.Errorf("status = %d, want 200", resp.StatusCode)
			}
			if elapsed := time.Since(start); elapsed > 30*time.Second {
				t.Errorf("waited %v; Retry-After was ignored in favour of the backoff", elapsed)
			}
		})
	}
}

// A cancelled caller must not be held for the rest of a backoff.
func TestStopsWaitingWhenTheContextEnds(t *testing.T) {
	next := &countingTransport{statuses: []int{503}}
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://example.test/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	cancel()

	opts := RetryOptions{Retries: 3, Backoff: time.Minute}
	start := time.Now()
	if _, err := (&RetryTransport{Next: next, Options: opts}).RoundTrip(req); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Errorf("waited %v after cancellation", elapsed)
	}
}

func TestNewHTTPClientAppliesTheTimeout(t *testing.T) {
	client := NewHTTPClient(RetryOptions{Retries: 1, Timeout: 7 * time.Second}, nil)
	if client.Timeout != 7*time.Second {
		t.Errorf("Timeout = %v, want 7s", client.Timeout)
	}
	if _, ok := client.Transport.(*RetryTransport); !ok {
		t.Errorf("Transport = %T, want *RetryTransport", client.Transport)
	}
}
