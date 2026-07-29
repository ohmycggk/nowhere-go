package bundle

import (
	"context"
	"net"

	"github.com/ohmycggk/nowhere-go/wire"
)

var _ func(*CarrierBundle, context.Context, wire.Target) (net.PacketConn, error) = (*CarrierBundle).OpenUDP
var _ func(*CarrierBundle, context.Context, wire.Target, []byte) (net.Conn, error) = (*CarrierBundle).OpenTCPWithPayload
