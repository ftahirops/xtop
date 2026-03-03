package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/ftahirops/xtop/model"
	"github.com/ftahirops/xtop/store"
)

// Client connects to the xtop daemon Unix socket API.
type Client struct {
	sockPath string
	http     *http.Client
}

// NewClient creates a new API client for the given socket path.
func NewClient(sockPath string) *Client {
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return net.DialTimeout("unix", sockPath, 5*time.Second)
		},
	}
	return &Client{
		sockPath: sockPath,
		http: &http.Client{
			Transport: transport,
			Timeout:   10 * time.Second,
		},
	}
}

// Ping checks if the daemon is reachable.
func (c *Client) Ping() error {
	resp, err := c.http.Get("http://xtop/v1/status")
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// Status returns the current health status.
func (c *Client) Status() (*StatusResponse, error) {
	var sr StatusResponse
	if err := c.getJSON("/v1/status", &sr); err != nil {
		return nil, err
	}
	return &sr, nil
}

// Top returns impact-scored process list.
func (c *Client) Top(limit int) ([]model.ImpactScore, error) {
	url := fmt.Sprintf("/v1/top?limit=%d", limit)
	var scores []model.ImpactScore
	if err := c.getJSON(url, &scores); err != nil {
		return nil, err
	}
	return scores, nil
}

// Incidents returns stored incidents.
func (c *Client) Incidents(limit int) ([]store.IncidentRecord, error) {
	url := fmt.Sprintf("/v1/incidents?limit=%d", limit)
	var records []store.IncidentRecord
	if err := c.getJSON(url, &records); err != nil {
		return nil, err
	}
	return records, nil
}

func (c *Client) getJSON(path string, out interface{}) error {
	resp, err := c.http.Get("http://xtop" + path)
	if err != nil {
		return fmt.Errorf("api request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("api error %d: %s", resp.StatusCode, string(body))
	}

	return json.NewDecoder(resp.Body).Decode(out)
}

// TryConnect attempts to connect to the daemon socket.
// Returns the client if successful, nil otherwise.
func TryConnect() *Client {
	sockPath := DefaultSockPath()
	c := NewClient(sockPath)
	if err := c.Ping(); err != nil {
		return nil
	}
	return c
}
