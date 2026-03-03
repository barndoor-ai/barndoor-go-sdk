package barndoor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// timeoutConfig configures timeouts for HTTP requests.
type timeoutConfig struct {
	read    time.Duration
	connect time.Duration
}

func defaultTimeoutConfig() timeoutConfig {
	return timeoutConfig{
		read:    30 * time.Second,
		connect: 10 * time.Second,
	}
}

// httpClient makes HTTP requests with automatic retry and error handling.
type httpClient struct {
	client     *http.Client
	timeout    timeoutConfig
	maxRetries int
	closed     bool
	logger     Logger
	sleepFunc  func(time.Duration) // overridable for testing
}

// httpRequestOptions holds options for an HTTP request.
type httpRequestOptions struct {
	Headers map[string]string
	JSON    any
	Params  map[string]string
}

func newHTTPClient(timeout timeoutConfig, maxRetries int) *httpClient {
	return &httpClient{
		client: &http.Client{
			Timeout: timeout.read + timeout.connect,
		},
		timeout:    timeout,
		maxRetries: maxRetries,
		logger:     createScopedLogger("http"),
		sleepFunc:  time.Sleep,
	}
}

func (c *httpClient) request(ctx context.Context, method, rawURL string, opts *httpRequestOptions) (json.RawMessage, error) {
	if c.closed {
		return nil, fmt.Errorf("HTTP client has been closed")
	}

	if opts == nil {
		opts = &httpRequestOptions{}
	}

	// Build URL with query parameters
	requestURL, err := c.buildURL(rawURL, opts.Params)
	if err != nil {
		return nil, err
	}

	var lastErr error

	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		// Prepare request body
		var body io.Reader
		if opts.JSON != nil {
			jsonBytes, err := json.Marshal(opts.JSON)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal JSON body: %w", err)
			}
			body = bytes.NewReader(jsonBytes)
		}

		req, err := http.NewRequestWithContext(ctx, strings.ToUpper(method), requestURL, body)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		// Set default headers
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "barndoor-go-sdk/"+Version)

		// Set custom headers
		for k, v := range opts.Headers {
			req.Header.Set(k, v)
		}

		resp, err := c.client.Do(req) // #nosec G704 -- URL built from validated SDK base URL
		if err != nil {
			if ctx.Err() != nil {
				lastErr = NewTimeoutError(fmt.Sprintf("Request to %s timed out", requestURL))
			} else {
				lastErr = NewConnectionError(requestURL, err)
			}

			if attempt == c.maxRetries {
				break
			}
			c.sleep(attempt)
			continue
		}

		respBody, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			lastErr = fmt.Errorf("failed to read response body: %w", err)
			if attempt == c.maxRetries {
				break
			}
			c.sleep(attempt)
			continue
		}

		// Handle HTTP errors
		if resp.StatusCode >= 400 {
			httpErr := NewHTTPError(resp.StatusCode, resp.Status, string(respBody))

			// 4xx errors are client errors - don't retry
			if resp.StatusCode >= 400 && resp.StatusCode < 500 {
				return nil, httpErr
			}

			// Retry 5xx errors only for idempotent methods
			if resp.StatusCode >= 500 && resp.StatusCode < 600 {
				upperMethod := strings.ToUpper(method)
				isIdempotent := upperMethod == "GET" || upperMethod == "HEAD" || upperMethod == "OPTIONS"
				if isIdempotent {
					lastErr = httpErr
					if attempt == c.maxRetries {
						break
					}
					c.sleep(attempt)
					continue
				}
				return nil, httpErr
			}

			return nil, httpErr
		}

		return json.RawMessage(respBody), nil
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("request to %s failed after %d attempts with no specific error", requestURL, c.maxRetries+1)
	}
	return nil, lastErr
}

func (c *httpClient) buildURL(baseURL string, params map[string]string) (string, error) {
	if len(params) == 0 {
		return baseURL, nil
	}

	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func (c *httpClient) sleep(attempt int) {
	delay := time.Duration(math.Min(float64(time.Second)*math.Pow(2, float64(attempt)), float64(10*time.Second)))
	c.sleepFunc(delay)
}

func (c *httpClient) close() {
	c.closed = true
	c.client.CloseIdleConnections()
}
