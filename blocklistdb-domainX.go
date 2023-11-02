package rdns

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/miekg/dns"
	"github.com/xtls/xray-core/app/router"
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
	loader BlocklistLoader
}

type nodeX map[string]nodeX

var _ BlocklistDB = &DomainXDB{}

func parseDomainRule(domain string) ([]*router.Domain, error) {
	if strings.HasPrefix(domain, "geosite:") {
		country := strings.ToUpper(domain[8:])
		domains, err := loadGeositeWithAttr("geosite.dat", country)
		if err != nil {
			return nil, fmt.Errorf("failed to load geosite: %s, err: %s", country, err)
		}
		return domains, nil
	}
	isExtDatFile := 0
	{
		const prefix = "ext:"
		if strings.HasPrefix(domain, prefix) {
			isExtDatFile = len(prefix)
		}
		const prefixQualified = "ext-domain:"
		if strings.HasPrefix(domain, prefixQualified) {
			isExtDatFile = len(prefixQualified)
		}
	}
	if isExtDatFile != 0 {
		kv := strings.Split(domain[isExtDatFile:], ":")
		if len(kv) != 2 {
			return nil, fmt.Errorf("invalid external resource: %s", domain)
		}
		filename := kv[0]
		country := kv[1]
		domains, err := loadGeositeWithAttr(filename, country)
		if err != nil {
			return nil, fmt.Errorf("failed to load external sites: %s from %s , err: %s", country, filename, err)
		}
		return domains, nil
	}

	domainRule := new(router.Domain)
	switch {
	case strings.HasPrefix(domain, "regexp:"):
		domainRule.Type = router.Domain_Regex
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "domain:"):
		domainRule.Type = router.Domain_Domain
		domainRule.Value = domain[7:]

	case strings.HasPrefix(domain, "full:"):
		domainRule.Type = router.Domain_Full
		domainRule.Value = domain[5:]

	case strings.HasPrefix(domain, "keyword:"):
		domainRule.Type = router.Domain_Plain
		domainRule.Value = domain[8:]

	case strings.HasPrefix(domain, "dotless:"):
		domainRule.Type = router.Domain_Regex
		switch substr := domain[8:]; {
		case substr == "":
			domainRule.Value = "^[^.]*$"
		case !strings.Contains(substr, "."):
			domainRule.Value = "^[^.]*" + substr + "[^.]*$"
		default:
			return nil, fmt.Errorf("substr in dotless rule should not contain a dot: %s", substr)
		}

	default:
		domainRule.Type = router.Domain_Plain
		domainRule.Value = domain
	}
	return []*router.Domain{domainRule}, nil
}

// NewDomainDB returns a new instance of a matcher for a list of regular expressions.
func NewDomainXDB(name string, loader BlocklistLoader) (*DomainXDB, error) {
	domains, err := loader.Load()
	if err != nil {
		return nil, err
	}
	sort.Strings(domains)

	Domains := []*router.Domain{}
	for _, domain := range domains {
		rules, err := parseDomainRule(domain)
		if err != nil {
			return nil, fmt.Errorf("failed to parse domain rule: %s, err: %s", domain, err)
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

func (m *DomainXDB) Match(q dns.Question) (net.IP, []string, *BlocklistMatch, bool) {
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