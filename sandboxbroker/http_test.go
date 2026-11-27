package sandboxbroker

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func brokerRequest(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestBrokerHTTPUsesOpaqueHandleWithoutCampaignSelectorOnRun(t *testing.T) {
	engine := &fakeEngine{}
	broker, err := New(engine, testImage)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newHTTPHandler(broker)
	if err != nil {
		t.Fatal(err)
	}
	created := brokerRequest(t, handler, http.MethodPost, "/v1/sandboxes", `{"campaign_id":42}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var result struct{ Handle string }
	if err := json.Unmarshal(created.Body.Bytes(), &result); err != nil || len(result.Handle) != 64 {
		t.Fatalf("opaque handle: %+v %v", result, err)
	}
	path := "/v1/sandboxes/" + result.Handle + "/run"
	bad := brokerRequest(t, handler, http.MethodPost, path, `{"command":"echo synthetic","campaign_id":99}`)
	if bad.Code != http.StatusBadRequest || engine.executed != 0 {
		t.Fatalf("accepted caller campaign selector: %d", bad.Code)
	}
	run := brokerRequest(t, handler, http.MethodPost, path, `{"command":"echo synthetic"}`)
	if run.Code != http.StatusOK || !bytes.Contains(run.Body.Bytes(), []byte("ran: echo synthetic")) {
		t.Fatalf("run: %d %s", run.Code, run.Body.String())
	}
	removed := brokerRequest(t, handler, http.MethodDelete, "/v1/sandboxes/"+result.Handle, "")
	if removed.Code != http.StatusNoContent || engine.removed != 1 {
		t.Fatalf("remove: %d removed=%d", removed.Code, engine.removed)
	}
	if got := brokerRequest(t, handler, http.MethodPost, path, `{"command":"echo again"}`); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("retired handle accepted: %d", got.Code)
	}
}

func TestBrokerHTTPRejectsMalformedAndOversizedRequests(t *testing.T) {
	broker, _ := New(&fakeEngine{}, testImage)
	handler, _ := newHTTPHandler(broker)
	for _, body := range []string{
		`{"campaign_id":0}`,
		`{"campaign_id":1,"extra":true}`,
		`{"campaign_id":1} {"campaign_id":2}`,
		`{"campaign_id":1` + strings.Repeat(" ", maxBrokerRequestBytes),
	} {
		got := brokerRequest(t, handler, http.MethodPost, "/v1/sandboxes", body)
		if got.Code != http.StatusBadRequest {
			t.Errorf("body length %d: status=%d", len(body), got.Code)
		}
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"campaign_id":1}`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("accepted missing content type: %d", response.Code)
	}
	if got := brokerRequest(t, handler, http.MethodGet, "/v1/sandboxes", ""); got.Code != http.StatusMethodNotAllowed {
		t.Fatalf("accepted unsupported method: %d", got.Code)
	}
}

func TestBrokerHTTPOmitsFailedCommandOutput(t *testing.T) {
	engine := &fakeEngine{failure: "exec"}
	broker, _ := New(engine, testImage)
	handler, _ := newHTTPHandler(broker)
	handle, err := broker.Create(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	got := brokerRequest(t, handler, http.MethodPost, "/v1/sandboxes/"+handle+"/run", `{"command":"false"}`)
	if got.Code != http.StatusServiceUnavailable || strings.Contains(got.Body.String(), "failure output") {
		t.Fatalf("failed command leaked output: %d %s", got.Code, got.Body.String())
	}
}
