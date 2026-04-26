package cmd

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

// pollHealth polls the hub /health endpoint until it returns 200 or the
// deadline (in seconds) elapses. Returns nil on success.
func pollHealth(url string, deadlineSec int) error {
	deadline := time.Now().Add(time.Duration(deadlineSec) * time.Second)
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		resp, err := client.Do(req)
		cancel()
		if err == nil && resp != nil {
			resp.Body.Close()
			if resp.StatusCode == 200 {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("hub did not become healthy within %ds", deadlineSec)
}
