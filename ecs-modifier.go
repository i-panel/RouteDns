package rdns

import (
	"errors"
	"net"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// ECSModifier manipulates EDNS0 Client Subnet in queries.
type ECSModifier struct {
	id       string
	resolver Resolver
	modifier ECSModifierFunc
}

var _ Resolver = &ECSModifier{}

// ECSModifierFunc takes a DNS query and modifies its EDN0 Client Subdomain record
type ECSModifierFunc func(id string, q *dns.Msg, ci ClientInfo)

// NewECSModifier initializes an ECS modifier.
func NewECSModifier(id string, resolver Resolver, f ECSModifierFunc) (*ECSModifier, error) {
	c := &ECSModifier{id: id, resolver: resolver, modifier: f}
	return c, nil
}

// Resolve modifies the OPT EDNS0 record and passes it to the next resolver.
func (r *ECSModifier) Resolve(q *dns.Msg, ci ClientInfo, PanelSocksDialer *Socks5Dialer) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}

	// Modify the query
	if r.modifier != nil {
		r.modifier(r.id, q, ci)
	}

	// Pass it on upstream
	return r.resolver.Resolve(q, ci, PanelSocksDialer)
}

func (r *ECSModifier) String() string {
	return r.id
}

// Check Cert
func (s *ECSModifier) CertMonitor() error {
	return nil
}

func ECSModifierDelete(id string, q *dns.Msg, ci ClientInfo) {
	edns0 := q.IsEdns0()
	if edns0 == nil {
		return
	}
	// Filter out any ECS options
	var hasECS bool
	newOpt := make([]dns.EDNS0, 0, len(edns0.Option))
	for _, opt := range edns0.Option {
		if _, ok := opt.(*dns.EDNS0_SUBNET); ok {
			hasECS = true
			continue
		}
		newOpt = append(newOpt, opt)
	}
	edns0.Option = newOpt

	// Only log if id is set to a non-empty string. Avoids double-logging
	// if called by other modifiers
	if hasECS && id != "" {
		logger(id, q, ci).Debug("removing ecs option")
	}
}

func ECSModifierAdd(addr net.IP, prefix4, prefix6 uint8) ECSModifierFunc {

	return func(id string, q *dns.Msg, ci ClientInfo) {
		// Drop any existing ECS options
		ECSModifierDelete("", q, ci)

		// If no address is configured, use that of the client
		sourceIP := addr
		if sourceIP == nil {
			sourceIP = ci.SourceIP
		}

		var (
			family uint16
			mask   uint8
		)
		if ip4 := sourceIP.To4(); len(ip4) == net.IPv4len {
			family = 1 // ip4
			sourceIP = ip4
			mask = prefix4
			sourceIP = sourceIP.Mask(net.CIDRMask(int(prefix4), 32))
		} else {
			family = 2 // ip6
			mask = prefix6
			sourceIP = sourceIP.Mask(net.CIDRMask(int(prefix6), 128))
		}

		// Add a new record if there's no EDNS0 at all
		edns0 := q.IsEdns0()
		if edns0 == nil {
			q.SetEdns0(4096, false)
			edns0 = q.IsEdns0()
		}

		// Append the ECS option
		ecs := new(dns.EDNS0_SUBNET)
		ecs.Code = dns.EDNS0SUBNET
		ecs.Family = family      // 1 for IPv4 source address, 2 for IPv6
		ecs.SourceNetmask = mask // 32 for IPV4, 128 for IPv6
		ecs.SourceScope = 0
		ecs.Address = sourceIP
		edns0.Option = append(edns0.Option, ecs)

		logger(id, q, ci).WithFields(logrus.Fields{
			"ecs":  sourceIP,
			"mask": mask,
		}).Debug("adding ecs option")
	}
}

func ECSModifierPrivacy(prefix4, prefix6 uint8) ECSModifierFunc {
	return func(id string, q *dns.Msg, ci ClientInfo) {
		edns0 := q.IsEdns0()
		if edns0 == nil {
			return
		}

		// Find the ECS option
		var (
			hasECS     bool
			beforeAddr net.IP
			afterAddr  net.IP
		)
		for _, opt := range edns0.Option {
			ecs, ok := opt.(*dns.EDNS0_SUBNET)
			if !ok {
				continue
			}
			switch ecs.Family {
			case 1: // ip4
				beforeAddr = ecs.Address.To4()
				afterAddr = beforeAddr.Mask(net.CIDRMask(int(prefix4), 32))
				ecs.Address = afterAddr
				ecs.SourceNetmask = prefix4
			case 2: // ip6
				beforeAddr = ecs.Address
				afterAddr = beforeAddr.Mask(net.CIDRMask(int(prefix6), 128))
				ecs.Address = afterAddr
				ecs.SourceNetmask = prefix6
			}
			hasECS = true
		}

		if hasECS {
			logger(id, q, ci).WithFields(logrus.Fields{
				"ip4prefix":   prefix4,
				"ip6prefix":   prefix6,
				"before-addr": beforeAddr,
				"after-addr":  afterAddr,
			}).Debug("modifying ecs privacy")
		}
	}
}
