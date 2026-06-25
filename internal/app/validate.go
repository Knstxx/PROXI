package app

import (
	"fmt"
	"net"
	"strings"
	"unicode"
)

func ValidateState(state State) error {
	switch state.Routes.Mode {
	case "", "direct", "selective", "force_proxy":
	default:
		return fmt.Errorf("unsupported routing mode %q", state.Routes.Mode)
	}
	if state.Routes.Mode != "direct" && state.Outbound == nil {
		return fmt.Errorf("external outbound link is not configured")
	}
	if state.Server.TProxyPort < 1 || state.Server.TProxyPort > 65535 {
		return fmt.Errorf("tproxy port must be 1-65535")
	}
	if state.Server.TProxyTable < 1 {
		return fmt.Errorf("tproxy table must be positive")
	}
	if state.Server.TProxyMark == "" || !strings.HasPrefix(state.Server.TProxyMark, "0x") {
		return fmt.Errorf("tproxy mark must be hexadecimal, e.g. 0x2333")
	}
	if _, _, err := net.ParseCIDR(state.Server.VPNSubnet); err != nil {
		return fmt.Errorf("vpn subnet: %w", err)
	}
	for _, user := range state.Server.Users {
		if err := validateUserName(user.Login); err != nil {
			return err
		}
		if len(user.Password) < 8 {
			return fmt.Errorf("password for %s is too short", user.Login)
		}
	}
	for _, v := range append(append([]string{}, state.Routes.ProxyDomains...), state.Routes.DirectDomains...) {
		if err := validateXrayDomain(v); err != nil {
			return err
		}
	}
	for _, v := range append(append([]string{}, state.Routes.ProxyIPs...), state.Routes.DirectIPs...) {
		if err := validateXrayIP(v); err != nil {
			return err
		}
	}
	if state.Routes.Mode == "selective" {
		for _, v := range state.Routes.ProxyDomains {
			if err := validateSelectiveProxyDomain(v); err != nil {
				return err
			}
		}
		for _, v := range state.Routes.ProxyIPs {
			if err := validateSelectiveProxyIP(v); err != nil {
				return err
			}
		}
	}
	for _, p := range state.Routes.ProxyPorts {
		if p < 1 || p > 65535 {
			return fmt.Errorf("proxy port out of range: %d", p)
		}
	}
	return nil
}

func validateSelectiveProxyDomain(v string) error {
	value := strings.ToLower(strings.TrimSpace(v))
	if strings.HasPrefix(value, "domain:") || strings.HasPrefix(value, "full:") || value == "geosite:ru-blocked-all" {
		return nil
	}
	return fmt.Errorf("selective mode cannot route %q before Xray; use domain:/full: rules, runetfreedom blocked lists, or Force Xray", v)
}

func validateSelectiveProxyIP(v string) error {
	value := strings.ToLower(strings.TrimSpace(v))
	if !strings.HasPrefix(value, "geoip:") {
		return nil
	}
	switch value {
	case "geoip:ru-blocked", "geoip:ru-blocked-community", "geoip:telegram":
		return nil
	default:
		return fmt.Errorf("selective mode cannot route %q before Xray; use IP/CIDR rules, runetfreedom blocked lists, or Force Xray", v)
	}
}

func validateUserName(v string) error {
	if v == "" {
		return fmt.Errorf("empty VPN username")
	}
	for _, r := range v {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			continue
		}
		return fmt.Errorf("VPN username %q contains unsupported character %q", v, r)
	}
	return nil
}

func validateXrayDomain(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("empty domain rule")
	}
	if strings.ContainsAny(v, " \t\r\n\"'`") {
		return fmt.Errorf("invalid domain rule %q", v)
	}
	for _, p := range []string{"domain:", "full:", "regexp:", "geosite:"} {
		if strings.HasPrefix(v, p) && len(v) > len(p) {
			return nil
		}
	}
	return nil
}

func validateXrayIP(v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("empty IP rule")
	}
	if strings.HasPrefix(v, "geoip:") && len(v) > len("geoip:") {
		return nil
	}
	if ip := net.ParseIP(v); ip != nil {
		return nil
	}
	if _, _, err := net.ParseCIDR(v); err == nil {
		return nil
	}
	return fmt.Errorf("invalid IP/CIDR/geoip rule %q", v)
}
