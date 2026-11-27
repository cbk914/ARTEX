// Package networkgateway exposes a campaign-bound TCP CONNECT transport for a
// trusted network edge. It is not connected to the ARTEX executor or Docker.
package networkgateway

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/Autumn-27/artex/networkpolicy"
)

type DialGate interface {
	Dial(context.Context, int64, string, string) (net.Conn, error)
}

type Limits struct {
	MaxConcurrent         int
	MaxBytesEachDirection int64
	MaxDuration           time.Duration
}

func (limits Limits) normalized() (Limits, error) {
	if limits.MaxConcurrent == 0 {
		limits.MaxConcurrent = 16
	}
	if limits.MaxBytesEachDirection == 0 {
		limits.MaxBytesEachDirection = 64 << 20
	}
	if limits.MaxDuration == 0 {
		limits.MaxDuration = 15 * time.Minute
	}
	if limits.MaxConcurrent < 1 || limits.MaxConcurrent > 128 ||
		limits.MaxBytesEachDirection < 1 || limits.MaxBytesEachDirection > 1<<30 ||
		limits.MaxDuration < time.Second || limits.MaxDuration > time.Hour {
		return Limits{}, errors.New("invalid gateway limits")
	}
	return limits, nil
}

type Gateway struct {
	campaignID int64
	gate       DialGate
	audit      networkpolicy.Audit
	limits     Limits
	slots      chan struct{}
}

// New binds every request on this gateway instance to one campaign. A future
// broker must bind its listener to only that campaign's private network.
func New(campaignID int64, gate DialGate, audit networkpolicy.Audit, limits Limits) (*Gateway, error) {
	if campaignID <= 0 || gate == nil || audit == nil {
		return nil, errors.New("gateway requires a campaign, policy gate and audit sink")
	}
	limits, err := limits.normalized()
	if err != nil {
		return nil, err
	}
	return &Gateway{campaignID: campaignID, gate: gate, audit: audit, limits: limits, slots: make(chan struct{}, limits.MaxConcurrent)}, nil
}

func (g *Gateway) auditEvent(reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = g.audit(ctx, networkpolicy.Denial{CampaignID: g.campaignID, Network: "tcp", Target: "<not-examined>", Reason: reason})
}

func (g *Gateway) reject(w http.ResponseWriter, reason string, status int) {
	g.auditEvent(reason)
	http.Error(w, http.StatusText(status), status)
}

func validConnectRequest(r *http.Request) bool {
	return r.ProtoMajor == 1 && r.URL != nil && r.URL.Host != "" &&
		r.Host == r.URL.Host && r.RequestURI == r.Host &&
		r.URL.User == nil && r.URL.Path == "" && r.URL.RawQuery == "" &&
		r.ContentLength <= 0 && len(r.TransferEncoding) == 0
}

func (g *Gateway) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		g.reject(w, "unsupported-method", http.StatusMethodNotAllowed)
		return
	}
	if !validConnectRequest(r) {
		g.reject(w, "invalid-connect-request", http.StatusBadRequest)
		return
	}
	select {
	case g.slots <- struct{}{}:
		defer func() { <-g.slots }()
	default:
		g.reject(w, "gateway-concurrency-limit", http.StatusTooManyRequests)
		return
	}
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		g.reject(w, "hijack-unavailable", http.StatusNotImplemented)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), g.limits.MaxDuration)
	defer cancel()
	peer, err := g.gate.Dial(ctx, g.campaignID, "tcp", r.Host)
	if err != nil {
		// The policy gate records its own bounded denial event. Never reflect its
		// internal errors or the requested host into an HTTP response.
		http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	defer peer.Close()
	deadline, _ := ctx.Deadline()
	if err := peer.SetDeadline(deadline); err != nil {
		g.reject(w, "peer-deadline-unavailable", http.StatusBadGateway)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer client.Close()
	if err := client.SetDeadline(deadline); err != nil {
		g.auditEvent("client-deadline-unavailable")
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	done := make(chan bool, 2)
	go func() {
		n, _ := io.Copy(peer, io.LimitReader(buffered, g.limits.MaxBytesEachDirection))
		if tcp, ok := peer.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- n >= g.limits.MaxBytesEachDirection
	}()
	go func() {
		n, _ := io.Copy(client, io.LimitReader(peer, g.limits.MaxBytesEachDirection))
		if tcp, ok := client.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		done <- n >= g.limits.MaxBytesEachDirection
	}()
	first, second := <-done, <-done
	if first || second {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = g.audit(ctx, networkpolicy.Denial{CampaignID: g.campaignID, Network: "tcp", Target: "<tunnel>", Reason: "tunnel-byte-limit"})
	}
}
