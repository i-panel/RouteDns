package rdns

import (
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// ClientAllowlist is a resolver that matches the IPs of clients against a allowlist
type ClientAllowlist struct {
	id string
	ClientAllowlistOptions
	resolver Resolver
	mu       sync.RWMutex
	metrics  *BlocklistMetrics
}

var _ Resolver = &ClientAllowlist{}

type ClientAllowlistOptions struct {
	// Optional, if the client is found to match the allowlist, send the query to this resolver.
	AllowlistResolver Resolver

	AllowlistDB IPBlocklistDB

	// Refresh period for the allowlist. Disabled if 0.
	AllowlistRefresh time.Duration
	AllowRemote bool
}

// NewClientAllowlist returns a new instance of a client allowlist resolver.
func NewClientAllowlist(id string, resolver Resolver, opt ClientAllowlistOptions) (*ClientAllowlist, error) {
	allowlist := &ClientAllowlist{
		id:                     id,
		resolver:               resolver,
		ClientAllowlistOptions: opt,
		metrics:                NewBlocklistMetrics(id),
	}

	// Start the refresh goroutines if we have a list and a refresh period was given
	if allowlist.AllowlistDB != nil && allowlist.AllowlistRefresh > 0 {
		go allowlist.refreshLoopAllowlist(allowlist.AllowlistRefresh)
	}
	return allowlist, nil
}

// Resolve a DNS query after checking the client's IP against a allowlist. Responds with
// REFUSED if the client IP is on the allowlist, or sends the query to an alternative
// resolver if one is configured.
func (r *ClientAllowlist) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if match, ok := r.AllowlistDB.Match(ci.SourceIP); ok {
		log := Log.WithFields(logrus.Fields{"id": r.id, "qname": qName(q), "list": match.List, "rule": match.Rule, "ip": ci.SourceIP})
		r.metrics.blocked.Add(1)
		if r.AllowlistResolver != nil {
			log.WithField("resolver", r.AllowlistResolver).Debug("client not on allowlist, forwarding to allowlist-resolver")
			return r.AllowlistResolver.Resolve(q, ci)
		}
		log.Debug("blocking client")
		return refused(q), nil
	}

	r.metrics.allowed.Add(1)
	return r.resolver.Resolve(q, ci)
}

func (r *ClientAllowlist) String() string {
	return r.id
}

func (r *ClientAllowlist) GetIPBlocklistDB() IPBlocklistDB {
	return r.ClientAllowlistOptions.AllowlistDB
}

func (r *ClientAllowlist) refreshLoopAllowlist(refresh time.Duration) {
	for {
		time.Sleep(refresh)
		log := Log.WithField("id", r.id)
		log.Debug("reloading allowlist")
		db, err := r.AllowlistDB.Reload()
		if err != nil {
			Log.WithError(err).Error("failed to load rules")
			continue
		}
		r.mu.Lock()
		r.AllowlistDB.Close()
		r.AllowlistDB = db
		r.mu.Unlock()
	}
}
