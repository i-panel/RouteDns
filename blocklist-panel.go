package rdns

import (
	"errors"
	"net"
	"reflect"
	"sync"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/service/controller"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

type PanellistOptions struct {

	// Optional, send anything that matches the allowlist to an
	// alternative resolver rather than the default upstream one.
	AllowListResolver Resolver

	// Rules that override the blocklist rules, effectively negate them.
	DB *PanelDB
	Loader *PanelLoader

	// alternative resolver rather than the default upstream one.
	BlockListResolver Resolver

	// Rules that override the blocklist rules, effectively negate them.
	// BlocklistDB BlocklistDB

	// Refresh period for the PanelDB. Disabled if 0.
	Refresh time.Duration

	// Optional, send anything that matches the allowlist to an
	// alternative resolver rather than the default upstream one.
	IpAllowListResolver Resolver

	// Rules that override the blocklist rules, effectively negate them.
	// IpAllowlistDB IPBlocklistDB
}

type PanelDB struct {
	AllowlistDB   BlocklistDB
	BlocklistDB   BlocklistDB
	IpAllowlistDB IPBlocklistDB

}

// Blocklist is a resolver that returns NXDOMAIN or a spoofed IP for every query that
// matches. Everything else is passed through to another resolver.
type Panellist struct {
	id string
	PanellistOptions
	resolver Resolver
	mu       sync.RWMutex
	metrics  *BlocklistMetrics
}

var _ Resolver = &Panellist{}

// NewBlocklist returns a new instance of a blocklist resolver.
func NewPanellist(id string, resolver Resolver, opt PanellistOptions) (*Panellist, error) {
	panellist := &Panellist{
		id:               id,
		resolver:         resolver,
		PanellistOptions: opt,
		metrics:          NewBlocklistMetrics(id),
	}

	// Start the refresh goroutines if we have a list and a refresh period was given

	if panellist.DB != nil && panellist.Refresh > 0 {
		go panellist.refreshLoop(panellist.Refresh)
	}
	return panellist, nil
}

// Resolve a DNS query by first checking the query against the provided matcher.
// Queries that do not match are passed on to the next resolver.
func (r *Panellist) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	if len(q.Question) < 1 {
		return nil, errors.New("no question in query")
	}
	question := q.Question[0]
	log := logger(r.id, q, ci)

	r.mu.RLock()
	allowlistDB := r.DB.AllowlistDB
	blocklistDB := r.DB.BlocklistDB
	ipallowlistDB := r.DB.IpAllowlistDB
	r.mu.RUnlock()

	// Forward to upstream or the optional ipallowlist-resolver immediately if there's a match in the ipallowlist
	if ipallowlistDB != nil {
		if match, ok := ipallowlistDB.Match(ci.SourceIP); !ok {
			log := Log.WithFields(logrus.Fields{"id": r.id, "qname": qName(q), "list": match.List, "rule": match.Rule, "ip": ci.SourceIP})
			
			if ipallowlistDB != nil {
				log.WithField("resolver", ipallowlistDB).Debug("client not on allowlist, forwarding to allowlist-resolver")
				return r.IpAllowListResolver.Resolve(q, ci)
			}

			r.metrics.blocked.Add(1)
			log.Debug("blocking client")
			return refused(q), nil
		}
	}

	// Forward to upstream or the optional allowlist-resolver immediately if there's a match in the allowlist
	if allowlistDB != nil {
		if ip, _, match, ok := allowlistDB.Match(question); ok {
			log = log.WithFields(logrus.Fields{"list": match.List, "rule": match.Rule})
			r.metrics.allowed.Add(1)
			if r.AllowListResolver != nil {
				log.WithField("resolver", r.AllowListResolver.String()).Debug("matched allowlist, forwarding")
				return r.AllowListResolver.Resolve(q, ci)
			}

			answer := new(dns.Msg)
			answer.SetReply(q)
			// We have an IP address to return, make sure it's of the right type. If not return NXDOMAIN.
			if ip4 := ip.To4(); len(ip4) == net.IPv4len && question.Qtype == dns.TypeA {
				answer.Answer = []dns.RR{
					&dns.A{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeA,
							Class:  question.Qclass,
							Ttl:    3600,
						},
						A: ip,
					},
				}
				log.Debug("spoofing response")
				return answer, nil
			} else if len(ip) == net.IPv6len && question.Qtype == dns.TypeAAAA {
				answer.Answer = []dns.RR{
					&dns.AAAA{
						Hdr: dns.RR_Header{
							Name:   question.Name,
							Rrtype: dns.TypeAAAA,
							Class:  question.Qclass,
							Ttl:    3600,
						},
						AAAA: ip,
					},
				}
				log.Debug("spoofing response")
				return answer, nil
			}
			log.WithField("resolver", r.resolver.String()).Debug("matched allowlist, forwarding")
			return r.resolver.Resolve(q, ci)
		}
	}
	
	ip, names, match, ok := blocklistDB.Match(question)
	if !ok {
		// Didn't match anything, pass it on to the next resolver
		log.WithField("resolver", r.resolver.String()).Debug("forwarding unmodified query to resolver")
		r.metrics.allowed.Add(1)
		return r.resolver.Resolve(q, ci)
	}
	log = log.WithFields(logrus.Fields{"list": match.List, "rule": match.Rule})
	r.metrics.blocked.Add(1)

	// If we got names for the PTR query, respond to it
	if question.Qtype == dns.TypePTR && len(names) > 0 {
		log.Debug("responding with ptr blocklist from blocklist")
		if len(names) > maxPTRResponses {
			names = names[:maxPTRResponses]
		}
		return ptr(q, names), nil
	}

	// If an optional blocklist-resolver was given, send the query to that instead of returning NXDOMAIN.
	if r.BlockListResolver != nil {
		log.WithField("resolver", r.BlockListResolver.String()).Debug("matched blocklist, forwarding")
		
		return r.BlockListResolver.Resolve(q, ci)
	}

	answer := new(dns.Msg)
	answer.SetReply(q)

	// We have an IP address to return, make sure it's of the right type. If not return NXDOMAIN.
	if ip4 := ip.To4(); len(ip4) == net.IPv4len && question.Qtype == dns.TypeA {
		answer.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  question.Qclass,
					Ttl:    3600,
				},
				A: ip,
			},
		}
		log.Debug("spoofing response")
		return answer, nil
	} else if len(ip) == net.IPv6len && question.Qtype == dns.TypeAAAA {
		answer.Answer = []dns.RR{
			&dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  question.Qclass,
					Ttl:    3600,
				},
				AAAA: ip,
			},
		}
		log.Debug("spoofing response")
		return answer, nil
	}

	// Block the request with NXDOMAIN if there was a match but no valid spoofed IP is given
	log.Debug("blocking request")
	answer.SetRcode(q, dns.RcodeNameError)
	return answer, nil
}

func (r *Panellist) String() string {
	return r.id
}

func (r *Panellist) refreshLoop(refresh time.Duration) (err error) {
	for {
		time.Sleep(refresh)
		log := Log.WithField("id", r.id)
		log.Debug("reloading IP allowlist")

		if err != nil {
			log.WithError(err).Error("failed to load rules")
			continue
		}

		// First fetch Node Info
		var nodeInfoChanged = true
		newNodeInfo, err := r.Loader.API.GetNodeInfo()
		if err != nil {
			if err.Error() == api.NodeNotModified {
				nodeInfoChanged = false
				newNodeInfo = r.Loader.opt.NodeInfo
			} else {
				log.WithError(err).Error("failed to load Panel rules")
				continue
			}
		}

		// Update User
		var usersChanged = true
		newUserInfo, err := r.Loader.API.GetUserList()
		if err != nil {
			if err.Error() == api.UserNotModified {
				usersChanged = false
				newUserInfo = r.Loader.opt.UserList
			} else {
				log.WithError(err).Error("failed to load Panel user list")
				continue
			}
		}

		// If nodeInfo changed
		if nodeInfoChanged {
			if !reflect.DeepEqual(r.Loader.opt.NodeInfo.RouteDNS, newNodeInfo.RouteDNS) {
				if !reflect.DeepEqual(r.Loader.opt.NodeInfo.RouteDNS.Allow, newNodeInfo.RouteDNS.Allow) {
					r.DB.AllowlistDB.Reload()
					nodeInfoChanged = true
				}
				if !reflect.DeepEqual(r.Loader.opt.NodeInfo.RouteDNS.Block, newNodeInfo.RouteDNS.Block) {
					nodeInfoChanged = true
				}
			} else {
				nodeInfoChanged = false
			}
		}

		var deleted, added []api.UserInfo
		if usersChanged {
			deleted, added = controller.CompareUserList(r.Loader.opt.UserList, newUserInfo)
			if len(deleted) > 0 {
				deletedUsers := make([]string, len(deleted))
				for i, u := range deleted {
					deletedUsers[i] = u.Passwd
				}
				r.mu.Lock()
				err := r.DB.IpAllowlistDB.Remove(deletedUsers)
				r.mu.Unlock()
				if err != nil {
					log.Print(err)
				}
			}
			if len(added) > 0 {
				addedUsers := make([]string, len(deleted))
				for i, u := range deleted {
					addedUsers[i] = u.Passwd
				}
				r.mu.Lock()
				err = r.DB.IpAllowlistDB.Add(addedUsers)
				r.mu.Unlock()
				if err != nil {
					log.Print(err)
				}
			}
		}
		log.Printf("%d user deleted, %d user added", len(deleted), len(added))

		
		r.mu.Lock()
		r.Loader.opt.UserList = newUserInfo
		r.Loader.opt.NodeInfo = newNodeInfo
		r.mu.Unlock()
	}
}
