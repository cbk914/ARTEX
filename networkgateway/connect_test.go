package networkgateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Autumn-27/artex/networkpolicy"
)

type ruleSource struct {
	mu    sync.Mutex
	rules []networkpolicy.Rule
}

func (s *ruleSource) LoadCampaignNetworkRules(_ context.Context, campaignID int64) ([]networkpolicy.Rule, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if campaignID != 9 {
		return nil, nil
	}
	return append([]networkpolicy.Rule(nil), s.rules...), nil
}

type fixedResolver struct{}

func (fixedResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
}

type rejectingGate struct{}

func (rejectingGate) Dial(context.Context, int64, string, string) (net.Conn, error) {
	return nil, networkpolicy.ErrDenied
}

type deadlineFailConn struct{ net.Conn }

func (deadlineFailConn) SetDeadline(time.Time) error { return fmt.Errorf("synthetic deadline failure") }

type deadlineFailGate struct{ conn net.Conn }

func (g deadlineFailGate) Dial(context.Context, int64, string, string) (net.Conn, error) {
	return g.conn, nil
}

type auditSink struct {
	mu      sync.Mutex
	reasons []string
}

func (a *auditSink) record(_ context.Context, event networkpolicy.Denial) error {
	a.mu.Lock()
	a.reasons = append(a.reasons, event.Reason)
	a.mu.Unlock()
	return nil
}
func (a *auditSink) has(reason string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, item := range a.reasons {
		if item == reason {
			return true
		}
	}
	return false
}

func localEcho(t *testing.T) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() { defer wg.Done(); defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener.Addr().String(), func() { listener.Close(); wg.Wait() }
}

func connect(t *testing.T, gatewayAddr, target string) (net.Conn, *bufio.Reader, string) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", gatewayAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	return conn, reader, status
}

func setupGateway(t *testing.T, limits Limits) (*httptest.Server, *ruleSource, *auditSink, string) {
	t.Helper()
	peer, closePeer := localEcho(t)
	t.Cleanup(closePeer)
	_, portText, _ := net.SplitHostPort(peer)
	port, _ := strconv.Atoi(portText)
	source := &ruleSource{rules: []networkpolicy.Rule{
		{Effect: "allow", TargetKind: "hostname", TargetValue: "target.test", Protocol: "tcp", PortStart: port, PortEnd: port, ExpiresAt: time.Now().Add(time.Hour)},
		{Effect: "allow", TargetKind: "cidr", TargetValue: "127.0.0.1/32", Protocol: "tcp", PortStart: port, PortEnd: port, ExpiresAt: time.Now().Add(time.Hour)},
	}}
	audit := &auditSink{}
	gate, err := networkpolicy.New(source, fixedResolver{}, &net.Dialer{}, audit.record)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := New(9, gate, audit.record, limits)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	t.Cleanup(server.Close)
	return server, source, audit, net.JoinHostPort("target.test", portText)
}

func TestConnectTunnelHonorsCurrentCampaignPolicy(t *testing.T) {
	server, source, audit, target := setupGateway(t, Limits{})
	conn, reader, status := connect(t, server.Listener.Addr().String(), target)
	if !strings.Contains(status, "200 Connection Established") {
		t.Fatalf("authorized CONNECT: %q", status)
	}
	if _, err := conn.Write([]byte("PING")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil || string(buf) != "PING" {
		t.Fatalf("tunnel echo: %q %v", buf, err)
	}
	conn.Close()

	_, portText, _ := net.SplitHostPort(target)
	direct, _, status := connect(t, server.Listener.Addr().String(), net.JoinHostPort("127.0.0.1", portText))
	direct.Close()
	if !strings.Contains(status, "403 Forbidden") {
		t.Fatalf("peer pin bypassed hostname: %q", status)
	}
	source.mu.Lock()
	source.rules = source.rules[:1] // revoke the peer decision; a new dial must fail.
	source.mu.Unlock()
	revoked, _, status := connect(t, server.Listener.Addr().String(), target)
	revoked.Close()
	if !strings.Contains(status, "403 Forbidden") || !audit.has("not-authorized") {
		t.Fatalf("revoked peer reached tunnel: %q", status)
	}
}

func TestConnectRejectsUnsupportedMethodsAndBoundsConcurrency(t *testing.T) {
	server, _, audit, target := setupGateway(t, Limits{MaxConcurrent: 1})
	first, _, status := connect(t, server.Listener.Addr().String(), target)
	if !strings.Contains(status, "200 Connection Established") {
		t.Fatalf("first CONNECT: %q", status)
	}
	second, _, status := connect(t, server.Listener.Addr().String(), target)
	second.Close()
	if !strings.Contains(status, "429 Too Many Requests") || !audit.has("gateway-concurrency-limit") {
		t.Fatalf("concurrency limit: %q", status)
	}
	first.Close()
	response, err := server.Client().Get(server.URL + "/http://target.test/")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 405 || !audit.has("unsupported-method") {
		t.Fatalf("unsupported method: %d", response.StatusCode)
	}
}

func TestConnectLimitsBytesAndRejectsInvalidSettings(t *testing.T) {
	for _, limits := range []Limits{{MaxConcurrent: 129}, {MaxBytesEachDirection: -1}, {MaxDuration: 2 * time.Hour}} {
		if _, err := New(9, rejectingGate{}, func(context.Context, networkpolicy.Denial) error { return nil }, limits); err == nil {
			t.Fatal("invalid gateway accepted")
		}
	}
	server, _, audit, target := setupGateway(t, Limits{MaxBytesEachDirection: 4})
	conn, reader, status := connect(t, server.Listener.Addr().String(), target)
	if !strings.Contains(status, "200 Connection Established") {
		t.Fatalf("limited CONNECT: %q", status)
	}
	if _, err := conn.Write([]byte("12345")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(reader, buf); err != nil || string(buf) != "1234" {
		t.Fatalf("bounded tunnel: %q %v", buf, err)
	}
	conn.Close()
	deadline := time.Now().Add(time.Second)
	for !audit.has("tunnel-byte-limit") && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !audit.has("tunnel-byte-limit") {
		t.Fatal("tunnel budget was not audited")
	}
}

func TestConnectRejectsAmbiguousAuthorityAndMissingDeadlines(t *testing.T) {
	r := httptest.NewRequest(http.MethodConnect, "http://target.test:443", nil)
	r.RequestURI = "target.test:443"
	r.Host = "other.test:443"
	if validConnectRequest(r) {
		t.Fatal("mismatched CONNECT authority accepted")
	}

	clientPeer, otherPeer := net.Pipe()
	defer otherPeer.Close()
	audit := &auditSink{}
	gateway, err := New(9, deadlineFailGate{deadlineFailConn{clientPeer}}, audit.record, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(gateway)
	defer server.Close()
	conn, _, status := connect(t, server.Listener.Addr().String(), "target.test:443")
	conn.Close()
	if !strings.Contains(status, "502 Bad Gateway") || !audit.has("peer-deadline-unavailable") {
		t.Fatalf("unbounded tunnel was accepted: %q", status)
	}
}
