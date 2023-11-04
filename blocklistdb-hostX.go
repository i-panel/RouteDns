package rdns

import (
	"fmt"
	"runtime"
	"sort"
	"strings"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/platform/filesystem"
	dnsf "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/protobuf/proto"
)

var (
	FileCache = make(map[string][]byte)
	// IPCache   = make(map[string]*router.GeoIP)
	SiteCache = make(map[string]*router.GeoSite)
)

// HostsDB holds a list of hosts-file entries that are used in blocklists to spoof or bloc requests.
// IP4 and IP6 records can be spoofed independently, however it's not possible to block only one type. If
// IP4 is given but no IP6, then a domain match will still result in an NXDOMAIN for the IP6 address.
type HostsXDB struct {
	name   string
	hosts  *StaticHosts
	loader BlocklistLoader
}

type AttributeList struct {
	matcher []conf.AttributeMatcher
}

type HostAddress struct {
	addr  *conf.Address
	addrs []*conf.Address
}

type HostsWrapper struct {
	Hosts map[string]*HostAddress
}

func find(data, code []byte) []byte {
	codeL := len(code)
	if codeL == 0 {
		return nil
	}
	for {
		dataL := len(data)
		if dataL < 2 {
			return nil
		}
		x, y := conf.DecodeVarint(data[1:])
		if x == 0 && y == 0 {
			return nil
		}
		headL, bodyL := 1+y, int(x)
		dataL -= headL
		if dataL < bodyL {
			return nil
		}
		data = data[headL:]
		if int(data[1]) == codeL {
			for i := 0; i < codeL && data[2+i] == code[i]; i++ {
				if i+1 == codeL {
					return data[:bodyL]
				}
			}
		}
		if dataL == bodyL {
			return nil
		}
		data = data[bodyL:]
	}
}

func loadFile(file string) ([]byte, error) {
	if FileCache[file] == nil {
		bs, err := filesystem.ReadAsset(file)
		if err != nil {
			return nil, fmt.Errorf("failed to open file:  %s, err: %s", file, err)
		}
		if len(bs) == 0 {
			return nil, fmt.Errorf("empty file: %s, err: %s", file, err)
		}
		// Do not cache file, may save RAM when there
		// are many files, but consume CPU each time.
		return bs, nil
		FileCache[file] = bs
	}
	return FileCache[file], nil
}

func loadSite(file, code string) ([]*router.Domain, error) {
	index := file + ":" + code
	if SiteCache[index] == nil {
		bs, err := loadFile(file)
		if err != nil {
			return nil, fmt.Errorf("failed to load file: %s, err: %s", file, err)
		}
		bs = find(bs, []byte(code))
		if bs == nil {
			return nil, fmt.Errorf("list not found in ", file, ": ", code)
		}
		var geosite router.GeoSite
		if err := proto.Unmarshal(bs, &geosite); err != nil {
			return nil, fmt.Errorf("error unmarshal Site in  %s : %s , err: %s", file, ": ", code, err)
		}
		defer runtime.GC()         // or debug.FreeOSMemory()
		return geosite.Domain, nil // do not cache geosite
		SiteCache[index] = &geosite
	}
	return SiteCache[index].Domain, nil
}

func (al *AttributeList) Match(domain *router.Domain) bool {
	for _, matcher := range al.matcher {
		if !matcher.Match(domain) {
			return false
		}
	}
	return true
}

func (al *AttributeList) IsEmpty() bool {
	return len(al.matcher) == 0
}

func parseAttrs(attrs []string) *AttributeList {
	al := new(AttributeList)
	for _, attr := range attrs {
		lc := strings.ToLower(attr)
		al.matcher = append(al.matcher, conf.BooleanMatcher(lc))
	}
	return al
}

func loadGeositeWithAttr(file string, siteWithAttr string) ([]*router.Domain, error) {
	parts := strings.Split(siteWithAttr, "@")
	if len(parts) == 0 {
		return nil, fmt.Errorf("empty site")
	}
	country := strings.ToUpper(parts[0])
	attrs := parseAttrs(parts[1:])
	domains, err := loadSite(file, country)
	if err != nil {
		return nil, err
	}

	if attrs.IsEmpty() {
		return domains, nil
	}

	filteredDomains := make([]*router.Domain, 0, len(domains))
	for _, domain := range domains {
		if attrs.Match(domain) {
			filteredDomains = append(filteredDomains, domain)
		}
	}

	return filteredDomains, nil
}

var typeMap = map[router.Domain_Type]dns.DomainMatchingType{
	router.Domain_Full:   dns.DomainMatchingType_Full,
	router.Domain_Domain: dns.DomainMatchingType_Subdomain,
	router.Domain_Plain:  dns.DomainMatchingType_Keyword,
	router.Domain_Regex:  dns.DomainMatchingType_Regex,
}

func getHostMapping(ha *HostAddress) *dns.Config_HostMapping {
	if ha.addr != nil {
		if ha.addr.Family().IsDomain() {
			return &dns.Config_HostMapping{
				ProxiedDomain: ha.addr.Domain(),
			}
		}
		return &dns.Config_HostMapping{
			Ip: [][]byte{ha.addr.IP()},
		}
	}

	ips := make([][]byte, 0, len(ha.addrs))
	for _, addr := range ha.addrs {
		if addr.Family().IsDomain() {
			return &dns.Config_HostMapping{
				ProxiedDomain: addr.Domain(),
			}
		}
		ips = append(ips, []byte(addr.IP()))
	}
	return &dns.Config_HostMapping{
		Ip: ips,
	}
}

func toNetIP(addrs []net.Address) ([]net.IP, error) {
	ips := make([]net.IP, 0, len(addrs))
	for _, addr := range addrs {
		if addr.Family().IsIP() {
			ips = append(ips, addr.IP())
		} else {
			return nil, fmt.Errorf("failed to convert address %s to Net IP", addr)
		}
	}
	return ips, nil
}

type StaticHosts struct {
	*dns.StaticHosts
}

// Build implements Buildable
func (m *HostsWrapper) Build() (*StaticHosts, error) {
	mappings := make([]*dns.Config_HostMapping, 0, 20)

	domains := make([]string, 0, len(m.Hosts))
	for domain := range m.Hosts {
		domains = append(domains, domain)
	}
	sort.Strings(domains)

	for _, domain := range domains {
		switch {
		case strings.HasPrefix(domain, "domain:"):
			domainName := domain[7:]
			if len(domainName) == 0 {
				return nil, fmt.Errorf("empty domain type of rule: %s", domain)
			}
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Subdomain
			mapping.Domain = domainName
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "geosite:"):
			listName := domain[8:]
			if len(listName) == 0 {
				return nil, fmt.Errorf("empty geosite rule: %s", domain)
			}
			geositeList, err := loadGeositeWithAttr("geosite.dat", listName)
			if err != nil {
				return nil, fmt.Errorf("failed to load geosite: %s, err: %s", listName, err)
			}
			for _, d := range geositeList {
				mapping := getHostMapping(m.Hosts[domain])
				mapping.Type = typeMap[d.Type]
				mapping.Domain = d.Value
				mappings = append(mappings, mapping)
			}

		case strings.HasPrefix(domain, "regexp:"):
			regexpVal := domain[7:]
			if len(regexpVal) == 0 {
				return nil, fmt.Errorf("empty regexp type of rule: %s", domain)
			}
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Regex
			mapping.Domain = regexpVal
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "keyword:"):
			keywordVal := domain[8:]
			if len(keywordVal) == 0 {
				return nil, fmt.Errorf("empty keyword type of rule: %s", domain)
			}
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Keyword
			mapping.Domain = keywordVal
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "full:"):
			fullVal := domain[5:]
			if len(fullVal) == 0 {
				return nil, fmt.Errorf("empty full domain type of rule: %s", domain)
			}
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Full
			mapping.Domain = fullVal
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "dotless:"):
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Regex
			switch substr := domain[8:]; {
			case substr == "":
				mapping.Domain = "^[^.]*$"
			case !strings.Contains(substr, "."):
				mapping.Domain = "^[^.]*" + substr + "[^.]*$"
			default:
				return nil, fmt.Errorf("substr in dotless rule should not contain a dot: %s", substr)
			}
			mappings = append(mappings, mapping)

		case strings.HasPrefix(domain, "ext:"):
			kv := strings.Split(domain[4:], ":")
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid external resource: %s", domain)
			}
			filename := kv[0]
			list := kv[1]
			geositeList, err := loadGeositeWithAttr(filename, list)
			if err != nil {
				return nil, fmt.Errorf("failed to load domain list: %s from %s , err: %s", list, filename, err)
			}
			for _, d := range geositeList {
				mapping := getHostMapping(m.Hosts[domain])
				mapping.Type = typeMap[d.Type]
				mapping.Domain = d.Value
				mappings = append(mappings, mapping)
			}

		default:
			mapping := getHostMapping(m.Hosts[domain])
			mapping.Type = dns.DomainMatchingType_Full
			mapping.Domain = domain
			mappings = append(mappings, mapping)
		}
	}
	hosts, err := dns.NewStaticHosts(mappings, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create hosts, rr: %s", err)
	}
	return &StaticHosts{hosts}, nil
}

var _ BlocklistDB = &HostsXDB{}

// NewHostsDB returns a new instance of a matcher for a list of regular expressions.
func NewHostsXDB(name string, loader BlocklistLoader) (*HostsXDB, error) {
	rules, err := loader.Load()
	if err != nil {
		return nil, err
	}
	hosts := map[string]*HostAddress{}
	for _, r := range rules {
		r = strings.TrimSpace(r)
		fields := strings.Fields(r)
		if len(fields) == 0 {
			continue
		}
		name := strings.TrimSuffix(fields[0], ".")
		ips := fields[1:]
		if strings.HasPrefix(name, "#") {
			continue
		}
		if len(ips) == 0 {
			continue
		}

		host := &HostAddress{}

		if len(ips) == 1 {
			addr := net.ParseAddress(ips[0])
			if addr.IP().IsUnspecified() {
				continue
			}

			if addr.Family().IsDomain() {
				return nil, fmt.Errorf("host domain mapping currently not supported, domain: %s", addr.Domain())
			}
			host.addr = &conf.Address{addr}
		} else if len(ips) > 1 {
			addrs := []*conf.Address{}
			for _, IPstring := range ips {
				addr := net.ParseAddress(IPstring)
				if addr.IP().IsUnspecified() {
					continue
				}

				if addr.Family().IsDomain() {
					return nil, fmt.Errorf("host domain mapping currently not supported, domain: %s", addr.Domain())
				}

				addrs = append(addrs, &conf.Address{addr})
			}
			host.addrs = addrs
		}
		hosts[name] = host
	}
	wrap := &HostsWrapper{hosts}
	staticHost, err := wrap.Build()
	if err != nil {
		return nil, err
	}
	return &HostsXDB{name, staticHost, loader}, nil
}

func (m *HostsXDB) Reload() (BlocklistDB, error) {
	return NewHostsXDB(m.name, m.loader)
}

func (m *HostsXDB) Match(q mdns.Question) (net.IP, []string, *BlocklistMatch, bool) {

	domain := strings.TrimSuffix(q.Name, ".")
	if domain == "" {
		return nil, nil, nil, false
	}

	option := dnsf.IPOption{
		IPv4Enable: q.Qtype == mdns.TypeA,
		IPv6Enable: q.Qtype == mdns.TypeAAAA,
	}
	if !option.IPv4Enable && !option.IPv6Enable {
		return nil, nil, nil, false
	}

	match := m.hosts.Lookup(domain, option)
	if len(match) == 0 {
		return nil, nil, nil, false
	}
	// Static host lookup
	ips, err := toNetIP(match)
	return ips[0],
		nil,
		&BlocklistMatch{
			List: m.name,
			Rule: ips[0].String() + " " + domain,
		},
		err == nil && len(ips) > 0
}

func (m *HostsXDB) String() string {
	return "HostsX"
}