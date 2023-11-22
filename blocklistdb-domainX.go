package rdns

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/infra/conf"
)

// DomainDB holds a list of domain strings (potentially with wildcards). Matching
// logic:
// domain.com: matches just domain.com and not subdomains
// .domain.com: matches domain.com and all subdomains
// *.domain.com: matches all subdomains but not domain.com
type DomainXDB struct {
	name   string
	// root   nodeX
	domains *router.DomainMatcher
	loader *PanelLoader
}

var _ BlocklistDB = &DomainXDB{}


// NewDomainDB returns a new instance of a matcher for a list of regular expressions.
func NewDomainXDB(name string, loader *PanelLoader) (*DomainXDB, error) {

	var domains []string
	switch loader.opt.Type {
	case "allow":
		domains = loader.opt.NodeInfo.RouteDNS.Allow.Domains
	case "block":
		domains = loader.opt.NodeInfo.RouteDNS.Block.Domains
	default:
		return nil, fmt.Errorf("unsupported format '%s'", loader.opt.Type)
	}
	// Define a Less function to sort based on the 'Rule' field
	lessFunc := func(i, j int) bool {
		return domains[i] < domains[j]
	}

	sort.Slice(domains, lessFunc)

	Domains := []*router.Domain{}
	for _, domain := range domains {
		rules, err := conf.ParseDomainRule(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to parse domain rule: %s, err: %S", domain, err)
		}
		Domains = append(Domains, rules...)
	}
	DomainMatcher, err := router.NewMphMatcherGroup(Domains)
	if err != nil {
		return nil, fmt.Errorf("failed to build domain matcher : %s", err)
	}

	return &DomainXDB{name, DomainMatcher, loader}, nil
}

func (m *DomainXDB) Reload() (BlocklistDB, error) {
	return NewDomainXDB(m.name, m.loader)
}

func (m *DomainXDB) Match(q dns.Question) ([]net.IP, []string, *BlocklistMatch, bool) {
	s := strings.TrimSuffix(q.Name, ".")
	

	return nil,
		nil,
		&BlocklistMatch{
			List: m.name,
			Rule: s,
		},
		m.domains.ApplyDomain(s)
}

func (m *DomainXDB) String() string {
	return "DomainX"
}