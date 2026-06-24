package core

import (
	"time"

	"vpnproxi/internal/link"
)

type State struct {
	Server    ServerConfig   `json:"server"`
	Outbound  *link.Outbound `json:"outbound,omitempty"`
	Routes    RouteConfig    `json:"routes"`
	UpdatedAt time.Time      `json:"updatedAt"`
}

type ServerConfig struct {
	VPNDomain      string    `json:"vpnDomain"`
	VPNSubnet      string    `json:"vpnSubnet"`
	VPNDNSServers  []string  `json:"vpnDnsServers"`
	MobikeEnabled  bool      `json:"mobikeEnabled"`
	CertFile       string    `json:"certFile"`
	KeyFile        string    `json:"keyFile"`
	CAFile         string    `json:"caFile"`
	XrayConfigPath string    `json:"xrayConfigPath"`
	SwanctlPath    string    `json:"swanctlPath"`
	UpdownPath     string    `json:"updownPath"`
	GeodataDir     string    `json:"geodataDir"`
	TProxyPort     int       `json:"tproxyPort"`
	TProxyMark     string    `json:"tproxyMark"`
	TProxyTable    int       `json:"tproxyTable"`
	UsersCSVPath   string    `json:"usersCsvPath"`
	Users          []VPNUser `json:"users"`
}

type VPNUser struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

type RouteConfig struct {
	Mode            string   `json:"mode"`
	DirectDomains   []string `json:"directDomains"`
	DirectIPs       []string `json:"directIps"`
	ProxyDomains    []string `json:"proxyDomains"`
	ProxyIPs        []string `json:"proxyIps"`
	ProxyPorts      []int    `json:"proxyPorts"`
	UseRunetGeodata bool     `json:"useRunetGeodata"`
	BlockPrivateIPs bool     `json:"blockPrivateIps"`
}

func DefaultState() State {
	return State{
		Server: ServerConfig{
			VPNSubnet:      "10.10.10.0/24",
			VPNDNSServers:  []string{"8.8.8.8", "1.1.1.1"},
			MobikeEnabled:  false,
			CertFile:       "/etc/swanctl/x509/vpnproxi-leaf.crt",
			KeyFile:        "/etc/swanctl/private/vpnproxi.key",
			CAFile:         "/etc/swanctl/x509ca/vpnproxi-ca.crt",
			XrayConfigPath: "/usr/local/etc/xray/config.json",
			SwanctlPath:    "/etc/swanctl/swanctl.conf",
			UpdownPath:     "/usr/local/bin/vpnproxi-updown.sh",
			GeodataDir:     "/usr/local/share/xray",
			TProxyPort:     10000,
			TProxyMark:     "0x2333",
			TProxyTable:    100,
			UsersCSVPath:   "/usr/local/etc/vpnproxi/users_traffic_route.csv",
			Users:          []VPNUser{},
		},
		Routes: RouteConfig{
			Mode:            "direct",
			UseRunetGeodata: true,
			BlockPrivateIPs: true,
			ProxyDomains: []string{
				"domain:whatismyipaddress.com",
				"domain:claude.ai",
				"domain:claude.com",
				"domain:anthropic.com",
			},
		},
		UpdatedAt: time.Now().UTC(),
	}
}
