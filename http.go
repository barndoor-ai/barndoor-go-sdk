package barndoor

import (
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"time"
)

// Retries live in a RoundTripper rather than a loop around each call, so a
// caller who brings their own *http.Client keeps them and pooling behaves the
// way net/http intends.

// RetryOptions is how hard to try. Retries=0 disables retrying.
type RetryOptions struct {
	// Retries is the number of attempts AFTER the first.
	Retries int
	// Timeout is the per-client timeout; zero means none.
	Timeout time.Duration
	// Backoff is the base for exponential backoff.
	Backoff time.Duration
}

// DefaultRetryOptions matches the other Barndoor SDKs.
func DefaultRetryOptions() RetryOptions {
	return RetryOptions{Retries: 3, Timeout: 30 * time.Second, Backoff: 250 * time.Millisecond}
}

// A 502 does not say whether the request reached the application, so retrying a
// POST risks a duplicate write. Only these are replayed.
var idempotent = map[string]bool{
	http.MethodGet:     true,
	http.MethodHead:    true,
	http.MethodOptions: true,
	http.MethodPut:     true,
	http.MethodDelete:  true,
}

// 501 and 505 are excluded: the server understood and will refuse identically.
func retryableStatus(status int) bool {
	if status == http.StatusTooManyRequests {
		return true
	}
	return status >= 500 && status != http.StatusNotImplemented && status != http.StatusHTTPVersionNotSupported
}

// RetryTransport wraps a RoundTripper and retries what is safe to retry.
type RetryTransport struct {
	Next    http.RoundTripper
	Options RetryOptions
}

// RoundTrip implements http.RoundTripper.
func (t *RetryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	next := t.Next
	if next == nil {
		next = http.DefaultTransport
	}

	// net/http leaves GetBody nil for an opaque stream, which the first attempt
	// has already consumed.
	replayable := req.Body == nil || req.Body == http.NoBody || req.GetBody != nil
	retryable := idempotent[req.Method] && replayable && t.Options.Retries > 0

	for attempt := 0; ; attempt++ {
		last := attempt >= t.Options.Retries

		attemptReq := req
		if attempt > 0 {
			var err error
			if attemptReq, err = rewind(req); err != nil {
				return nil, err
			}
		}

		resp, err := next.RoundTrip(attemptReq)
		if err != nil {
			// A transport error says nothing about whether the request was
			// applied, so the same rule governs it.
			if last || !retryable {
				return nil, err
			}
			if werr := wait(req, t.backoff(attempt)); werr != nil {
				return nil, err
			}
			continue
		}

		if last || !retryable || !retryableStatus(resp.StatusCode) {
			return resp, nil
		}

		delay := t.backoff(attempt)
		if after, ok := retryAfter(resp); ok {
			delay = after
		}
		// Undrained, the connection never returns to the pool and a burst of
		// 503s becomes connection exhaustion.
		drain(resp)

		if err := wait(req, delay); err != nil {
			return nil, err
		}
	}
}

// rewind produces a fresh request: the RoundTripper contract forbids mutating
// the one it was handed, and a consumed body cannot be re-read.
func rewind(req *http.Request) (*http.Request, error) {
	clone := req.Clone(req.Context())
	if req.GetBody == nil {
		return clone, nil
	}
	body, err := req.GetBody()
	if err != nil {
		return nil, err
	}
	clone.Body = body
	return clone, nil
}

// wait sleeps unless the context ends first.
func wait(req *http.Request, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-req.Context().Done():
		return req.Context().Err()
	}
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	_ = resp.Body.Close()
}

// backoff is exponential with jitter, so clients of a service that just
// returned 503 do not come back in lockstep.
func (t *RetryTransport) backoff(attempt int) time.Duration {
	base := t.Options.Backoff
	if base <= 0 {
		base = DefaultRetryOptions().Backoff
	}
	//nolint:gosec // jitter, not a secret
	return time.Duration(float64(base) * float64(int64(1)<<uint(attempt)) * (0.5 + rand.Float64()))
}

// retryAfter reads the header, which is either seconds or an HTTP date.
func retryAfter(resp *http.Response) (time.Duration, bool) {
	header := resp.Header.Get("Retry-After")
	if header == "" {
		return 0, false
	}
	if secs, err := strconv.ParseFloat(header, 64); err == nil {
		return max(0, time.Duration(secs*float64(time.Second))), true
	}
	if at, err := http.ParseTime(header); err == nil {
		return max(0, time.Until(at)), true
	}
	return 0, false
}

// NewHTTPClient returns an *http.Client that retries. base goes underneath.
func NewHTTPClient(opts RetryOptions, base http.RoundTripper) *http.Client {
	if base == nil {
		base = http.DefaultTransport
	}
	transport := base
	if opts.Retries > 0 {
		transport = &RetryTransport{Next: base, Options: opts}
	}
	return &http.Client{Transport: transport, Timeout: opts.Timeout}
}
