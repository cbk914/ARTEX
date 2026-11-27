// Package networkpolicy evaluates campaign egress decisions for a trusted
// gateway. No ARTEX executor currently routes sockets through this package.
package networkpolicy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var ErrDenied = errors.New("campaign network connection denied")

type Rule struct {
	Effect, TargetKind, TargetValue, Protocol string
	PortStart, PortEnd                        int
	AllowDirect                               bool
	ExpiresAt                                 time.Time
}

// Source must read current decisions for every new connection.
type Source interface {
	LoadCampaignNetworkRules(context.Context, int64) ([]Rule, error)
}

type Resolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

type Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

type Denial struct {
	CampaignID              int64
	Network, Target, Reason string
}

type Audit func(context.Context, Denial) error

type Gate struct {
	source   Source
	resolver Resolver
	dialer   Dialer
	audit    Audit
}

func New(source Source, resolver Resolver, dialer Dialer, audit Audit) (*Gate, error) {
	if source == nil || resolver == nil || dialer == nil || audit == nil {
		return nil, errors.New("network gate requires policy source, resolver, dialer and audit sink")
	}
	return &Gate{source: source, resolver: resolver, dialer: dialer, audit: audit}, nil
}

func (g *Gate) deny(campaignID int64, network, target, reason string) (net.Conn, error) {
	target = auditTarget(target)
	auditCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := g.audit(auditCtx, Denial{campaignID, network, target, reason}); err != nil {
		return nil, errors.Join(fmt.Errorf("%w: %s", ErrDenied, reason), fmt.Errorf("record denial: %w", err))
	}
	return nil, fmt.Errorf("%w: %s", ErrDenied, reason)
}

func auditTarget(target string) string {
	host, portText, err := net.SplitHostPort(target)
	if err != nil {
		return "<invalid>"
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return "<invalid>"
	}
	if address, err := netip.ParseAddr(host); err == nil && address.Zone() == "" {
		return net.JoinHostPort(address.Unmap().String(), strconv.Itoa(port))
	}
	host, err = NormalizeTarget("hostname", host)
	if err != nil {
		return "<invalid>"
	}
	return net.JoinHostPort(host, strconv.Itoa(port))
}

// NormalizeTarget accepts exact ASCII hostnames, unzoned IPs and CIDRs.
func NormalizeTarget(kind, raw string) (string, error) {
	value := strings.TrimSpace(raw)
	switch kind {
	case "ip":
		address, err := netip.ParseAddr(value)
		if err != nil || address.Zone() != "" {
			return "", errors.New("invalid network IP target")
		}
		return address.Unmap().String(), nil
	case "cidr":
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Addr().Zone() != "" || prefix.Addr().Is4In6() {
			return "", errors.New("invalid network CIDR target")
		}
		return prefix.Masked().String(), nil
	case "hostname":
		value = strings.TrimSuffix(strings.ToLower(value), ".")
		if len(value) == 0 || len(value) > 253 {
			return "", errors.New("invalid network hostname")
		}
		if _, err := netip.ParseAddr(value); err == nil {
			return "", errors.New("IP literal must use the IP target kind")
		}
		for _, label := range strings.Split(value, ".") {
			if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
				return "", errors.New("invalid network hostname label")
			}
			for _, char := range label {
				if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
					return "", errors.New("invalid network hostname label")
				}
			}
		}
		return value, nil
	default:
		return "", errors.New("invalid network target kind")
	}
}

func validRule(rule Rule) bool {
	if rule.Effect != "allow" && rule.Effect != "deny" {
		return false
	}
	if rule.Protocol != "tcp" && rule.Protocol != "udp" {
		return false
	}
	if rule.PortStart < 1 || rule.PortEnd > 65535 || rule.PortEnd < rule.PortStart {
		return false
	}
	if rule.AllowDirect && rule.TargetKind == "hostname" {
		return false
	}
	value, err := NormalizeTarget(rule.TargetKind, rule.TargetValue)
	return err == nil && value == rule.TargetValue
}

func matches(rule Rule, hostname string, peer netip.Addr, network string, port int, now time.Time) bool {
	if rule.Protocol != network || port < rule.PortStart || port > rule.PortEnd || !rule.ExpiresAt.After(now) {
		return false
	}
	switch rule.TargetKind {
	case "hostname":
		return hostname != "" && rule.TargetValue == hostname
	case "ip":
		return rule.TargetValue == peer.String()
	case "cidr":
		prefix, _ := netip.ParsePrefix(rule.TargetValue) // validRule checked it.
		return prefix.Contains(peer)
	default:
		return false
	}
}

func allowed(rules []Rule, hostname string, peer netip.Addr, network string, port int, now time.Time) bool {
	var hostAllowed, peerAllowed bool
	for _, rule := range rules {
		if !matches(rule, hostname, peer, network, port, now) {
			continue
		}
		if rule.Effect == "deny" {
			return false
		}
		if rule.TargetKind == "hostname" {
			hostAllowed = true
		} else if hostname != "" || rule.AllowDirect {
			peerAllowed = true
		}
	}
	return peerAllowed && (hostname == "" || hostAllowed)
}

func hostnameApproved(rules []Rule, hostname, network string, port int, now time.Time) bool {
	approved := false
	for _, rule := range rules {
		if rule.TargetKind != "hostname" || !matches(rule, hostname, netip.Addr{}, network, port, now) {
			continue
		}
		if rule.Effect == "deny" {
			return false
		}
		approved = true
	}
	return approved
}

// Dial requires every DNS answer to be authorized, then dials a numeric peer.
// The policy source is read anew for every call; a failed read denies egress.
func (g *Gate) Dial(ctx context.Context, campaignID int64, network, target string) (net.Conn, error) {
	if campaignID <= 0 || (network != "tcp" && network != "udp") {
		return g.deny(campaignID, network, target, "invalid-request")
	}
	host, portText, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return g.deny(campaignID, network, target, "invalid-destination")
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return g.deny(campaignID, network, target, "invalid-port")
	}
	var hostname string
	var peers []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Zone() != "" {
			return g.deny(campaignID, network, target, "zoned-address")
		}
		peers = []netip.Addr{ip.Unmap()}
	} else {
		hostname, err = NormalizeTarget("hostname", host)
		if err != nil {
			return g.deny(campaignID, network, target, "invalid-hostname")
		}
	}
	rules, err := g.source.LoadCampaignNetworkRules(ctx, campaignID)
	if err != nil {
		return g.deny(campaignID, network, target, "policy-unavailable")
	}
	if len(rules) > 4096 {
		return g.deny(campaignID, network, target, "policy-too-large")
	}
	for _, rule := range rules {
		if !validRule(rule) {
			return g.deny(campaignID, network, target, "invalid-policy")
		}
	}
	now := time.Now()
	if hostname != "" {
		if !hostnameApproved(rules, hostname, network, port, now) {
			return g.deny(campaignID, network, target, "hostname-not-authorized")
		}
		peers, err = g.resolver.LookupNetIP(ctx, "ip", hostname)
		if err != nil || len(peers) == 0 || len(peers) > 64 {
			return g.deny(campaignID, network, target, "dns-unavailable")
		}
	}
	for i, peer := range peers {
		if !peer.IsValid() || peer.Zone() != "" {
			return g.deny(campaignID, network, target, "invalid-dns-answer")
		}
		peers[i] = peer.Unmap()
		if !allowed(rules, hostname, peers[i], network, port, now) {
			return g.deny(campaignID, network, target, "not-authorized")
		}
	}
	return g.dialer.DialContext(ctx, network, net.JoinHostPort(peers[0].String(), strconv.Itoa(port)))
}
