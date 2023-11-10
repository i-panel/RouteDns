package rdns

import (
	"fmt"
	"net"
	"strings"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/infra/conf"
)

// CidrDB holds a list of IP networks that are used to block matching DNS responses.
// Network ranges are stored in a trie (one for IP4 and one for IP6) to allow for
// efficient matching
type CidrDBX struct {
	name   string
	cidrs  []*router.GeoIPMatcher
	loader BlocklistLoader
}

var _ IPBlocklistDB = &CidrDBX{}

func (db *CidrDBX) Add(rules []string) error {
	for _, cidr := range db.cidrs {
		if cidr.GetCountryCode() != "panel" {continue}
		cidr.Add(rules)
	}
	return nil
}

func (db *CidrDBX) Remove(ips []string) error {
	for _, cidr := range db.cidrs {
		err, _ := cidr.Remove(ips)
		if err != nil {
			return nil
		}
	}
	return nil
}

func ToCidrList(ips conf.StringList) ([]*router.GeoIP, error) {
	var geoipList []*router.GeoIP
	var customCidrs []*router.CIDR

	for _, ip := range ips {
		if strings.HasPrefix(ip, "geoip:") {
			country := ip[6:]
			isReverseMatch := false
			if strings.HasPrefix(ip, "geoip:!") {
				country = ip[7:]
				isReverseMatch = true
			}
			if len(country) == 0 {
				return nil, fmt.Errorf("empty country name in rule")
			}
			geoip, err := conf.LoadGeoIP("geoip.dat", strings.ToUpper(country))
			if err != nil {
				return nil, fmt.Errorf("failed to load GeoIP: %s, error: %s", country, err)
			}

			geoipList = append(geoipList, &router.GeoIP{
				CountryCode:  strings.ToUpper(country),
				Cidr:         geoip,
				ReverseMatch: isReverseMatch,
			})
			continue
		}
		isExtDatFile := 0
		{
			const prefix = "ext:"
			if strings.HasPrefix(ip, prefix) {
				isExtDatFile = len(prefix)
			}
			const prefixQualified = "ext-ip:"
			if strings.HasPrefix(ip, prefixQualified) {
				isExtDatFile = len(prefixQualified)
			}
		}
		if isExtDatFile != 0 {
			kv := strings.Split(ip[isExtDatFile:], ":")
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid external resource: %s", ip)
			}

			filename := kv[0]
			country := kv[1]
			if len(filename) == 0 || len(country) == 0 {
				return nil, fmt.Errorf("empty filename or empty country in rule")
			}

			isReverseMatch := false
			if strings.HasPrefix(country, "!") {
				country = country[1:]
				isReverseMatch = true
			}
			geoip, err := conf.LoadGeoIP(filename, strings.ToUpper(country))
			if err != nil {
				return nil, fmt.Errorf("failed to load IPs: %s from %s , error: %s", country, filename, err)
			}

			geoipList = append(geoipList, &router.GeoIP{
				CountryCode:  strings.ToUpper(filename + "_" + country),
				Cidr:         geoip,
				ReverseMatch: isReverseMatch,
			})

			continue
		}

		ipRule, err := conf.ParseIP(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid IP: %s , error: %s", ip, err)
		}
		customCidrs = append(customCidrs, ipRule)
	}

	if len(customCidrs) > 0 {
		geoipList = append(geoipList, &router.GeoIP{
			CountryCode: "panel",
			Cidr:        customCidrs,
		})
	}

	return geoipList, nil
}

// NewCidrDB returns a new instance of a matcher for a list of networks.
// func NewCidrDBX(name string, IPs conf.StringList, loader *PanelLoader) (*CidrDBX, error) {
func NewCidrDBX(name string, loader *PanelLoader) (*CidrDBX, error) {

	IPs := conf.StringList{}

	for _, user := range *loader.opt.UserList {
		IPs = append(IPs, user.Passwd)
	}
	container := new(router.GeoIPMatcherContainer)
	geoipList, err := ToCidrList(IPs)
	if err != nil {
		return nil, err
	}
	var matchers []*router.GeoIPMatcher
	for _, geoip := range geoipList {
		matcher, err := container.Add(geoip)
		if err != nil {
			return nil, fmt.Errorf("failed to create ip matcher, error: %s", err)
		}
		matchers = append(matchers, matcher)
	}
	return &CidrDBX{name, matchers, loader}, nil
}

func (m *CidrDBX) Reload() (IPBlocklistDB, error) {
	return NewCidrDB(m.name, m.loader)
}

func (m *CidrDBX) Match(ip net.IP) (*BlocklistMatch, bool) {
	if len(m.cidrs) == 0 {
		return &BlocklistMatch{List: m.name, Rule: ip.DefaultMask().String()}, false
	}

	ok := false
	for _, matcher := range m.cidrs {
		if matcher.Match(ip) {
			ok = true
			break
		}
	}

	return &BlocklistMatch{List: m.name, Rule: ip.DefaultMask().String()}, ok
}

func (m *CidrDBX) Close() error {
	return nil
}

func (m *CidrDBX) String() string {
	return "CIDR-Panel"
}
