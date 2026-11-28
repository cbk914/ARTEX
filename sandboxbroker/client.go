package sandboxbroker

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
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
		Output   string `json:"output"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal(data, &result); err != nil || len(result.Output) > maxDockerOutput || result.ExitCode < 0 || result.ExitCode > 255 {
		return "", errors.New("broker returned invalid command output")
	}
	if result.ExitCode != 0 {
		return result.Output, &CommandExitError{Code: result.ExitCode}
	}
	return result.Output, nil
}

func (c *Client) RunInput(ctx context.Context, handle, command string, input []byte) (string, error) {
	if !ownershipToken.MatchString(handle) || command == "" || len(command) > 64<<10 || strings.IndexByte(command, 0) >= 0 || len(input) == 0 || len(input) > maxBrokerStdinBytes {
		return "", errors.New("invalid broker stdin execution request")
	}
	data, err := c.request(ctx, http.MethodPost, "/v1/sandboxes/"+handle+"/run-input", struct {
		Command string `json:"command"`
		Input   []byte `json:"input"`
	}{command, input}, http.StatusOK)
	if err != nil {
		return "", err
	}
	var result struct {
		Output   string `json:"output"`
		ExitCode int    `json:"exit_code"`
	}
	if err := json.Unmarshal(data, &result); err != nil || len(result.Output) > maxDockerOutput || result.ExitCode < 0 || result.ExitCode > 255 {
		return "", errors.New("broker returned invalid command output")
	}
	if result.ExitCode != 0 {
		return result.Output, &CommandExitError{Code: result.ExitCode}
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

// PutArtifact sends one bounded immutable artifact to an authorized sandbox.
// The caller must already have bound the handle to a live campaign grant.
func (c *Client) PutArtifact(ctx context.Context, handle, name string, data []byte) (string, error) {
	if !ownershipToken.MatchString(handle) || !validArtifactName(name) || len(data) == 0 || len(data) > maxArtifactBytes {
		return "", errors.New("invalid broker artifact request")
	}
	response, err := c.doRequest(ctx, http.MethodPut, "/v1/sandboxes/"+handle+"/artifacts/"+name, bytes.NewReader(data), "application/octet-stream", http.StatusCreated)
	if err != nil {
		return "", err
	}
	var result struct {
		SHA256 string `json:"sha256"`
	}
	if err := json.Unmarshal(response, &result); err != nil {
		return "", errors.New("broker returned invalid artifact digest")
	}
	local := sha256.Sum256(data)
	if result.SHA256 != hex.EncodeToString(local[:]) {
		return "", errors.New("broker returned mismatched artifact digest")
	}
	return result.SHA256, nil
}

// PutUpload streams an already authorized attachment without buffering it in
// the client. The broker verifies its exact length and digest before publish.
func (c *Client) PutUpload(ctx context.Context, handle, name string, input io.Reader, size int64, digest string) error {
	if !ownershipToken.MatchString(handle) || !validCampaignUploadName(name) || input == nil || size < 0 || size > maxCampaignUploadBytes || !uploadDigest.MatchString(digest) {
		return errors.New("invalid broker upload request")
	}
	var body io.Reader = io.LimitReader(input, size+1)
	if size == 0 {
		empty := sha256.Sum256(nil)
		var probe [1]byte
		n, readErr := input.Read(probe[:])
		if digest != hex.EncodeToString(empty[:]) || n != 0 || readErr != io.EOF {
			return errors.New("invalid empty broker upload")
		}
		body = bytes.NewReader(nil)
	}
	putCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	request, err := http.NewRequestWithContext(putCtx, http.MethodPut, "http://broker/v1/sandboxes/"+handle+"/uploads/"+url.PathEscape(name), body)
	if err != nil {
		return errors.New("invalid broker upload request")
	}
	request.ContentLength = size
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("X-Artex-SHA256", digest)
	uploadClient := *c.http
	uploadClient.Timeout = 0 // putCtx, rather than the short control-call timer, bounds streaming.
	response, err := uploadClient.Do(request)
	if err != nil {
		return errors.New("broker upload unavailable")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1025))
	if err != nil || len(data) > 1024 || response.StatusCode != http.StatusCreated {
		return errors.New("broker upload rejected")
	}
	var result struct {
		SHA256 string `json:"sha256"`
	}
	if json.Unmarshal(data, &result) != nil || result.SHA256 != digest {
		return errors.New("broker upload digest mismatch")
	}
	return nil
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
	contentType := ""
	if body != nil {
		contentType = "application/json"
	}
	return c.doRequest(ctx, method, path, reader, contentType, wantStatus)
}

func (c *Client) doRequest(ctx context.Context, method, path string, reader io.Reader, contentType string, wantStatus int) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://broker"+path, reader)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
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
