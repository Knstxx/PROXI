package app

import "vpnproxi/internal/core"

type State = core.State
type ServerConfig = core.ServerConfig
type VPNUser = core.VPNUser
type RouteConfig = core.RouteConfig

func DefaultState() State {
	return core.DefaultState()
}
