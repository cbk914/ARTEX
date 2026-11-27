package sandboxbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const maxBrokerResponseBytes = 8 << 20

// Client is a control-plane-only broker client. It never dials TCP, follows a
// redirect or accepts a caller-supplied campaign selector for Run or Remove.
type Client struct {
	http      *http.Client
	transport *http.Transport
}

func NewUnixClient(path string) (*Client, error) {
	if err := validateBrokerClientSocketPath(path); err != nil {
		return nil, err
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if err := validateBrokerClientSocketPath(path); err != nil {
				return nil, err
			}
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		},
	}
	return &Client{
		transport: transport,
		http: &http.Client{
			Transport:     transport,
			Timeout:       60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}, nil
}

func (c *Client) Close() { c.transport.CloseIdleConnections() }

func (c *Client) Create(ctx context.Context, campaignID int64) (string, error) {
	if campaignID <= 0 {
		return "", errors.New("invalid campaign ID")
	}
	data, err := c.request(ctx, http.MethodPost, "/v1/sandboxes", struct {
		CampaignID int64 `json:"campaign_id"`
	}{campaignID}, http.StatusCreated)
	if err != nil {
		return "", err
	}
	var result struct {
		Handle string `json:"handle"`
	}
	if err := json.Unmarshal(data, &result); err != nil || !ownershipToken.MatchString(result.Handle) {
		return "", errors.New("broker returned invalid handle")
	}
	return result.Handle, nil
}

func (c *Client) Run(ctx context.Context, handle, command string) (string, error) {
	if !ownershipToken.MatchString(handle) || command == "" || len(command) > 64<<10 || strings.IndexByte(command, 0) >= 0 {
		return "", errors.New("invalid broker execution request")
	}
	data, err := c.request(ctx, http.MethodPost, "/v1/sandboxes/"+handle+"/run", struct {
		Command string `json:"command"`
	}{command}, http.StatusOK)
	if err != nil {
		return "", err
	}
	var result struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(data, &result); err != nil || len(result.Output) > maxDockerOutput {
		return "", errors.New("broker returned invalid command output")
	}
	return result.Output, nil
}

func (c *Client) Remove(ctx context.Context, handle string) error {
	if !ownershipToken.MatchString(handle) {
		return errors.New("invalid sandbox handle")
	}
	_, err := c.request(ctx, http.MethodDelete, "/v1/sandboxes/"+handle, nil, http.StatusNoContent)
	return err
}

func (c *Client) request(ctx context.Context, method, path string, body any, wantStatus int) ([]byte, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://broker"+path, reader)
	if err != nil {
		return nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.http.Do(request)
	if err != nil {
		// net/http includes the request URL in its error, which contains the
		// opaque handle on Run and Remove. Keep that capability out of logs.
		return nil, errors.New("broker unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxBrokerResponseBytes+1))
	if err != nil || len(data) > maxBrokerResponseBytes {
		return nil, errors.New("broker response unavailable or oversized")
	}
	if response.StatusCode != wantStatus {
		return nil, fmt.Errorf("broker request denied: HTTP %d", response.StatusCode)
	}
	return data, nil
}
