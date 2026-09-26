// Package client talks to the panel's /agent/v1 API (SPEC §8).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/billyriantono/dnsjos/internal/shared/api"
)

type Client struct {
	BaseURL string // https://panel.example
	Token   string // node bearer token; empty for enroll
	Version string // agent version, sent as X-Dnsjos-Agent
	HTTP    *http.Client
	// Attempts per JSON call (network errors, 429 and 5xx are retried). Default 4.
	Attempts int
}

func New(baseURL, token, version string) *Client {
	// TLS verification stays on: the default transport verifies the panel certificate.
	return &Client{BaseURL: strings.TrimRight(baseURL, "/"), Token: token, Version: version, HTTP: &http.Client{}}
}

// StatusError is a non-2xx/304 panel answer.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string { return fmt.Sprintf("panel: HTTP %d: %s", e.Code, e.Body) }

// Permanent reports whether retrying the same request cannot help (4xx except 408/429).
func Permanent(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code >= 400 && se.Code < 500 && se.Code != 408 && se.Code != 429
}

// NewRequest builds a request against the panel with the agent headers set.
func (c *Client) NewRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	u := path
	if !strings.HasPrefix(path, "http://") && !strings.HasPrefix(path, "https://") {
		u = c.BaseURL + path
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if c.Token != "" {
		req.Header.Set("Authorization", "Bearer "+c.Token)
	}
	req.Header.Set(api.AgentHeader, c.Version)
	return req, nil
}

// Do sends one request without retries (streaming downloads).
func (c *Client) Do(req *http.Request) (*http.Response, error) { return c.HTTP.Do(req) }

// JSON sends in (if non-nil) and decodes a 2xx body into out (if non-nil). A 304 returns
// (304, nil) without decoding. Transient failures are retried with jittered backoff.
func (c *Client) JSON(ctx context.Context, method, path string, in, out any, hdr http.Header) (int, http.Header, error) {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return 0, nil, err
		}
	}
	attempts := c.Attempts
	if attempts <= 0 {
		attempts = 4
	}
	var lastErr error
	for i := range attempts {
		if i > 0 {
			d := time.Second << (i - 1)
			d += rand.N(d) // jitter so a fleet does not retry in lockstep
			select {
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			case <-time.After(d):
			}
		}
		code, h, err := c.once(ctx, method, path, body, out, hdr)
		if err == nil || ctx.Err() != nil || Permanent(err) {
			return code, h, err
		}
		lastErr = err
	}
	return 0, nil, lastErr
}

func (c *Client) once(ctx context.Context, method, path string, body []byte, out any, hdr http.Header) (int, http.Header, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := c.NewRequest(ctx, method, path, rd)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified:
		return resp.StatusCode, resp.Header, nil
	case resp.StatusCode >= 300:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return resp.StatusCode, resp.Header, &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(b))}
	case out != nil && resp.StatusCode != http.StatusNoContent:
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return resp.StatusCode, resp.Header, fmt.Errorf("panel: decode %s: %w", path, err)
		}
	}
	return resp.StatusCode, resp.Header, nil
}

func (c *Client) Enroll(ctx context.Context, req api.EnrollRequest) (api.EnrollResponse, error) {
	var out api.EnrollResponse
	_, _, err := c.JSON(ctx, http.MethodPost, "/agent/v1/enroll", req, &out, nil)
	return out, err
}

// Config fetches the desired config; version is the last seen one (0 = none).
// nil config with nil error means 304 (unchanged).
func (c *Client) Config(ctx context.Context, version int) (*api.AgentConfig, error) {
	var hdr http.Header
	if version > 0 {
		hdr = http.Header{"If-None-Match": {`"` + strconv.Itoa(version) + `"`}}
	}
	var out api.AgentConfig
	code, _, err := c.JSON(ctx, http.MethodGet, "/agent/v1/config", nil, &out, hdr)
	if err != nil || code == http.StatusNotModified {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Heartbeat(ctx context.Context, hb *api.Heartbeat) (api.HeartbeatAck, error) {
	var out api.HeartbeatAck
	_, _, err := c.JSON(ctx, http.MethodPost, "/agent/v1/heartbeat", hb, &out, nil)
	return out, err
}

// IdempotencyHeader carries a batch's key; it is the same on every retry and replay of
// that batch, so the panel can skip a batch it already committed.
const IdempotencyHeader = "Idempotency-Key"

func (c *Client) PostBlocked(ctx context.Context, key string, b api.BlockedBatch) error {
	_, _, err := c.JSON(ctx, http.MethodPost, "/agent/v1/blocked", b, nil, http.Header{IdempotencyHeader: {key}})
	return err
}

func (c *Client) PostAnalytics(ctx context.Context, key string, b api.AnalyticsBatch) error {
	_, _, err := c.JSON(ctx, http.MethodPost, "/agent/v1/analytics", b, nil, http.Header{IdempotencyHeader: {key}})
	return err
}

func (c *Client) PostCGK(ctx context.Context, r api.CGKReport) error {
	_, _, err := c.JSON(ctx, http.MethodPost, "/agent/v1/cgk", r, nil, nil)
	return err
}

// Allowlist fetches the active allowlist; version is the applied one ("" = none). nil
// with nil error means 304 (unchanged).
func (c *Client) Allowlist(ctx context.Context, version string) (*api.Allowlist, error) {
	var hdr http.Header
	if version != "" {
		hdr = http.Header{"If-None-Match": {`"` + strings.Trim(version, `"`) + `"`}}
	}
	var out api.Allowlist
	code, _, err := c.JSON(ctx, http.MethodGet, "/agent/v1/allowlist", nil, &out, hdr)
	if err != nil || code == http.StatusNotModified {
		return nil, err
	}
	return &out, nil
}
