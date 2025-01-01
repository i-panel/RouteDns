package rdns

import (
	"fmt"
	"strings"

	mdns "github.com/miekg/dns"
	"github.com/xtls/xray-core/app/dns"
	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/net"
	dnsf "github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/infra/conf"
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
	hosts  *dns.StaticHosts
	loader *PanelLoader
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

var _ BlocklistDB = &HostsXDB{}

// NewHostsDB returns a new instance of a matcher for a list of regular expressions.
func NewHostsXDB(name string, loader *PanelLoader) (*HostsXDB, error) {

	var hosts *conf.HostsWrapper
	switch name {
	case "allow":
		hosts = loader.opt.NodeInfo.RouteDNS.Allow.Hosts
	case "block":
		hosts = loader.opt.NodeInfo.RouteDNS.Block.Hosts
	default:
		return nil, fmt.Errorf("unsupported format '%s'", loader.opt.Type)
	}
	mappings, err := hosts.Build()
	if err != nil {
		return nil, err
	}
	staticHosts, err := dns.NewStaticHosts(mappings, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create hosts, rr: %s", err)
	}
	return &HostsXDB{name, staticHosts, loader}, nil
}

func (m *HostsXDB) Reload() (BlocklistDB, error) {
	return NewHostsXDB(m.name, m.loader)
}

func (m *HostsXDB) Match(q mdns.Question) ([]net.IP, []string, *BlocklistMatch, bool) {

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
	return ips,
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