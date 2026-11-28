package sandboxbroker

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

// A 64 KiB command can expand to six JSON bytes per control character.
const maxBrokerRequestBytes = 512 << 10
const maxBrokerInputRequestBytes = 2 << 20

// newHTTPHandler exposes only the broker's opaque-handle lifecycle. It has no
// HTTP authentication and must only be used by the root-only Unix listener.
func newHTTPHandler(broker *Broker) (http.Handler, error) {
	if broker == nil {
		return nil, errors.New("broker is required")
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/sandboxes", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			CampaignID int64 `json:"campaign_id"`
		}
		if !decodeBrokerRequest(w, r, &input) {
			return
		}
		if input.CampaignID <= 0 {
			writeBrokerError(w, http.StatusBadRequest, "invalid campaign")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		handle, err := broker.Create(ctx, input.CampaignID)
		if err != nil {
			writeBrokerError(w, http.StatusServiceUnavailable, "sandbox unavailable")
			return
		}
		writeBrokerJSON(w, http.StatusCreated, struct {
			Handle string `json:"handle"`
		}{handle})
	})
	mux.HandleFunc("POST /v1/sandboxes/{handle}/run", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Command string `json:"command"`
		}
		if !decodeBrokerRequest(w, r, &input) {
			return
		}
		if input.Command == "" || len(input.Command) > 64<<10 || strings.IndexByte(input.Command, 0) >= 0 {
			writeBrokerError(w, http.StatusBadRequest, "invalid command")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		output, err := broker.Run(ctx, r.PathValue("handle"), input.Command)
		if err != nil {
			var exit *CommandExitError
			if errors.As(err, &exit) && exit.Code > 0 && exit.Code <= 255 && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, errDockerOutputLimit) {
				writeBrokerJSON(w, http.StatusOK, struct {
					Output   string `json:"output"`
					ExitCode int    `json:"exit_code"`
				}{output, exit.Code})
				return
			}
			// Command output may contain sensitive target data. Do not expose it
			// through a generic error response.
			writeBrokerError(w, http.StatusServiceUnavailable, "sandbox execution failed")
			return
		}
		writeBrokerJSON(w, http.StatusOK, struct {
			Output   string `json:"output"`
			ExitCode int    `json:"exit_code"`
		}{output, 0})
	})
	mux.HandleFunc("POST /v1/sandboxes/{handle}/run-input", func(w http.ResponseWriter, r *http.Request) {
		var input struct {
			Command string `json:"command"`
			Input   []byte `json:"input"`
		}
		if !decodeBrokerRequestLimit(w, r, &input, maxBrokerInputRequestBytes) {
			return
		}
		if input.Command == "" || len(input.Command) > 64<<10 || strings.IndexByte(input.Command, 0) >= 0 || len(input.Input) == 0 || len(input.Input) > maxBrokerStdinBytes {
			writeBrokerError(w, http.StatusBadRequest, "invalid stdin execution")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
		defer cancel()
		output, err := broker.RunInput(ctx, r.PathValue("handle"), input.Command, input.Input)
		if err != nil {
			var exit *CommandExitError
			if errors.As(err, &exit) && exit.Code > 0 && exit.Code <= 255 && !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, errDockerOutputLimit) {
				writeBrokerJSON(w, http.StatusOK, struct {
					Output   string `json:"output"`
					ExitCode int    `json:"exit_code"`
				}{output, exit.Code})
				return
			}
			writeBrokerError(w, http.StatusServiceUnavailable, "sandbox execution failed")
			return
		}
		writeBrokerJSON(w, http.StatusOK, struct {
			Output   string `json:"output"`
			ExitCode int    `json:"exit_code"`
		}{output, 0})
	})
	mux.HandleFunc("PUT /v1/sandboxes/{handle}/artifacts/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		if !validArtifactName(name) || r.Header.Get("Content-Type") != "application/octet-stream" || r.ContentLength > maxArtifactBytes {
			writeBrokerError(w, http.StatusBadRequest, "invalid artifact")
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxArtifactBytes+1))
		if err != nil || len(data) == 0 || len(data) > maxArtifactBytes {
			writeBrokerError(w, http.StatusBadRequest, "invalid artifact")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 50*time.Second)
		defer cancel()
		if err := broker.PutArtifact(ctx, r.PathValue("handle"), name, data); err != nil {
			writeBrokerError(w, http.StatusServiceUnavailable, "sandbox artifact unavailable")
			return
		}
		digest := sha256.Sum256(data)
		writeBrokerJSON(w, http.StatusCreated, struct {
			SHA256 string `json:"sha256"`
		}{hex.EncodeToString(digest[:])})
	})
	mux.HandleFunc("PUT /v1/sandboxes/{handle}/uploads/{name}", func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("name")
		digest := r.Header.Get("X-Artex-SHA256")
		if !validCampaignUploadName(name) || r.Header.Get("Content-Type") != "application/octet-stream" || r.ContentLength < 0 || r.ContentLength > maxCampaignUploadBytes || !uploadDigest.MatchString(digest) {
			writeBrokerError(w, http.StatusBadRequest, "invalid campaign upload")
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
		defer cancel()
		if err := broker.PutUpload(ctx, r.PathValue("handle"), name, http.MaxBytesReader(w, r.Body, maxCampaignUploadBytes+1), r.ContentLength, digest); err != nil {
			writeBrokerError(w, http.StatusServiceUnavailable, "campaign upload unavailable")
			return
		}
		writeBrokerJSON(w, http.StatusCreated, struct {
			SHA256 string `json:"sha256"`
		}{digest})
	})
	mux.HandleFunc("DELETE /v1/sandboxes/{handle}", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := broker.Remove(ctx, r.PathValue("handle")); err != nil {
			writeBrokerError(w, http.StatusServiceUnavailable, "sandbox unavailable")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux, nil
}

func decodeBrokerRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	return decodeBrokerRequestLimit(w, r, dst, maxBrokerRequestBytes)
}

func decodeBrokerRequestLimit(w http.ResponseWriter, r *http.Request, dst any, limit int64) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeBrokerError(w, http.StatusUnsupportedMediaType, "JSON required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, limit))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		writeBrokerError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeBrokerError(w, http.StatusBadRequest, "one JSON object required")
		return false
	}
	return true
}

func writeBrokerError(w http.ResponseWriter, code int, message string) {
	writeBrokerJSON(w, code, struct {
		Error string `json:"error"`
	}{message})
}

func writeBrokerJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
