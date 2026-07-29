package app

import (
	"strings"
	"testing"

	"vpnproxi/internal/link"
)

func TestValidateStateRejectsDomainRuleInjection(t *testing.T) {
	state := DefaultState()
	state.Routes.ProxyDomains = []string{"domain:example.com\nserver=/bad/1.1.1.1"}

	err := ValidateState(state)
	if err == nil || !strings.Contains(err.Error(), "invalid domain rule") {
		t.Fatalf("ValidateState() error = %v", err)
	}
}

func TestValidateStateAllowsXrayCategoriesInSelectiveMode(t *testing.T) {
	state := DefaultState()
	state.Routes.Mode = "selective"
	state.Outbound = mustTestOutbound()
	state.Routes.ProxyDomains = []string{"geosite:youtube"}
	state.Routes.ProxyIPs = []string{"geoip:google"}
	if err := ValidateState(state); err != nil {
		t.Fatalf("ValidateState() error = %v", err)
	}
}

func TestValidateStateAllowsRunetFreedomSelectiveProxyRules(t *testing.T) {
	state := DefaultState()
	state.Routes.Mode = "selective"
	state.Outbound = mustTestOutbound()
	state.Routes.ProxyDomains = []string{"geosite:ru-blocked-all", "domain:youtube.com", "full:www.youtube.com"}
	state.Routes.ProxyIPs = []string{"geoip:ru-blocked", "geoip:ru-blocked-community", "geoip:telegram", "203.0.113.0/24"}

	if err := ValidateState(state); err != nil {
		t.Fatalf("ValidateState() error = %v", err)
	}
}

func mustTestOutbound() *link.Outbound {
	out, err := link.Parse("vless://11111111-2222-4333-8444-555555555555@example.com:443?type=tcp&security=none#node")
	if err != nil {
		panic(err)
	}
	return out
}
