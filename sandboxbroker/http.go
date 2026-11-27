package sandboxbroker

import (
	"context"
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
			// Command output may contain sensitive target data. Do not expose it
			// through a generic error response.
			writeBrokerError(w, http.StatusServiceUnavailable, "sandbox execution failed")
			return
		}
		writeBrokerJSON(w, http.StatusOK, struct {
			Output string `json:"output"`
		}{output})
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
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		writeBrokerError(w, http.StatusUnsupportedMediaType, "JSON required")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBrokerRequestBytes))
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
