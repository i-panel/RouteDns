package rdns

import (
	"fmt"

	"github.com/miekg/dns"
)

// Resolver is an interface to resolve DNS queries.
type Resolver interface {
	Resolve(*dns.Msg, ClientInfo, *Socks5Dialer) (*dns.Msg, error)
	CertMonitor() error
	fmt.Stringer
}