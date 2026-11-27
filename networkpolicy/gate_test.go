package networkpolicy

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"
)

type fixtureSource struct {
	rules map[int64][]Rule
	err   error
	reads int
}

func (s *fixtureSource) LoadCampaignNetworkRules(_ context.Context, campaignID int64) ([]Rule, error) {
	s.reads++
	return append([]Rule(nil), s.rules[campaignID]...), s.err
}

type fixtureResolver struct {
	answers []netip.Addr
	err     error
	reads   int
}

func (r *fixtureResolver) LookupNetIP(_ context.Context, _, _ string) ([]netip.Addr, error) {
	r.reads++
	return append([]netip.Addr(nil), r.answers...), r.err
}

type fixtureDialer struct {
	addresses []string
	inner     net.Dialer
}

func (d *fixtureDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	d.addresses = append(d.addresses, network+" "+address)
	return d.inner.DialContext(ctx, network, address)
}

func rule(effect, kind, value, protocol string, port int) Rule {
	return Rule{Effect: effect, TargetKind: kind, TargetValue: value, Protocol: protocol,
		PortStart: port, PortEnd: port, ExpiresAt: time.Now().Add(time.Hour)}
}

func TestGatePinsAuthorizedLocalPeerAndFailsClosed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	name := "target.test"
	ip := netip.MustParseAddr("127.0.0.1")
	host := rule("allow", "hostname", name, "tcp", port)
	peer := rule("allow", "cidr", "127.0.0.1/32", "tcp", port)
	source := &fixtureSource{rules: map[int64][]Rule{1: {host, peer}}}
	resolver := &fixtureResolver{answers: []netip.Addr{ip}}
	dialer := &fixtureDialer{}
	var denials []Denial
	gate, err := New(source, resolver, dialer, func(_ context.Context, event Denial) error {
		denials = append(denials, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	target := net.JoinHostPort(name, strconv.Itoa(port))
	conn, err := gate.Dial(context.Background(), 1, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	if len(dialer.addresses) != 1 || dialer.addresses[0] != "tcp 127.0.0.1:"+strconv.Itoa(port) {
		t.Fatalf("dial was not pinned to the checked IP: %v", dialer.addresses)
	}
	if source.reads != 1 || resolver.reads != 1 {
		t.Fatalf("unexpected reads: policy=%d dns=%d", source.reads, resolver.reads)
	}

	assertDenied := func(campaignID int64, destination string) {
		t.Helper()
		before := len(dialer.addresses)
		if conn, err := gate.Dial(context.Background(), campaignID, "tcp", destination); !errors.Is(err, ErrDenied) || conn != nil {
			t.Fatalf("unexpected network grant for %d %s: conn=%v err=%v", campaignID, destination, conn, err)
		}
		if len(dialer.addresses) != before {
			t.Fatal("denied destination reached dialer")
		}
	}
	assertDenied(1, net.JoinHostPort("127.0.0.1", strconv.Itoa(port))) // peer pin is not direct-IP approval.
	assertDenied(2, target)                                            // another campaign has no inherited authorization.
	beforeDNS := resolver.reads
	assertDenied(1, net.JoinHostPort("sibling.test", strconv.Itoa(port)))
	assertDenied(1, net.JoinHostPort(name, strconv.Itoa(port+1)))
	if resolver.reads != beforeDNS {
		t.Fatal("unapproved hostname reached DNS resolver")
	}
	resolver.answers = []netip.Addr{ip, netip.MustParseAddr("127.0.0.2")}
	assertDenied(1, target) // a partial DNS answer cannot be selected opportunistically.
	resolver.answers = []netip.Addr{ip}
	source.rules[1] = append(source.rules[1], rule("deny", "ip", "127.0.0.1", "tcp", port))
	assertDenied(1, target)        // explicit deny overrides both allows.
	source.rules[1] = []Rule{host} // a revoked peer approval affects the next connection.
	assertDenied(1, target)
	source.err = errors.New("synthetic policy store outage")
	assertDenied(1, target)
	source.err = nil
	host.ExpiresAt = time.Now().Add(-time.Second)
	source.rules[1] = []Rule{host, peer}
	assertDenied(1, target)
	if len(denials) != 9 || denials[len(denials)-1].Reason != "hostname-not-authorized" {
		t.Fatalf("blocked connection audit: %+v", denials)
	}
}

func TestGateAllowsExplicitDirectIPAndUDP(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	port := packet.LocalAddr().(*net.UDPAddr).Port
	direct := rule("allow", "cidr", "127.0.0.1/32", "udp", port)
	direct.AllowDirect = true
	source := &fixtureSource{rules: map[int64][]Rule{1: {direct}}}
	gate, err := New(source, &fixtureResolver{}, &net.Dialer{}, func(context.Context, Denial) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	conn, err := gate.Dial(context.Background(), 1, "udp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err := packet.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 32)
	n, _, err := packet.ReadFrom(buf)
	if err != nil || string(buf[:n]) != "synthetic" {
		t.Fatalf("UDP peer did not receive packet: %q %v", buf[:n], err)
	}
}

func TestGateRejectsInvalidPolicyAndAuditOutage(t *testing.T) {
	source := &fixtureSource{rules: map[int64][]Rule{1: {{Effect: "allow", TargetKind: "cidr", TargetValue: "bad-prefix", Protocol: "tcp", PortStart: 80, PortEnd: 80, ExpiresAt: time.Now().Add(time.Hour)}}}}
	var reasons []string
	gate, err := New(source, &fixtureResolver{}, &net.Dialer{}, func(_ context.Context, event Denial) error {
		reasons = append(reasons, event.Reason)
		return errors.New("synthetic audit outage")
	})
	if err != nil {
		t.Fatal(err)
	}
	if conn, err := gate.Dial(context.Background(), 1, "tcp", "127.0.0.1:80"); !errors.Is(err, ErrDenied) || conn != nil || len(reasons) != 1 || reasons[0] != "invalid-policy" {
		t.Fatalf("invalid policy/audit failure did not deny: %v %v %v", conn, err, reasons)
	}
	if _, err := New(source, &fixtureResolver{}, &net.Dialer{}, nil); err == nil {
		t.Fatal("accepted missing audit sink")
	}
}

func TestAuditTargetDropsMalformedInput(t *testing.T) {
	if got := auditTarget("user:secret@host:443"); got != "<invalid>" {
		t.Fatalf("untrusted destination exposed in audit: %q", got)
	}
	if got := auditTarget("TARGET.test.:0443"); got != "target.test:443" {
		t.Fatalf("valid destination was not normalized: %q", got)
	}
}
