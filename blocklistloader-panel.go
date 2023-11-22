package rdns

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/sspanel"
	"github.com/txthinking/socks5"
)

// HTTPLoader reads blocklist rules from a server via HTTP(S).
type PanelLoader struct {
	API         *sspanel.APIClient
	opt         PanelLoaderOptions
	fromDisk    bool
	lastSuccess []string
}

// HTTPLoaderOptions holds options for HTTP blocklist loaders.
type PanelLoaderOptions struct {
	CacheDir        string
	BlocklistFormat string
	AllowlistFormat string
	NodeInfo        *api.NodeInfo
	UserList        *[]api.UserInfo
	// DB *PanelDB
	Type string

	// Don't fail when trying to load the list
	AllowFailure bool
}

var _ BlocklistLoader = &PanelLoader{}

// const httpTimeout = 30 * time.Minute

func NewPanelLoader(api *sspanel.APIClient, opt PanelLoaderOptions) *PanelLoader {
	return &PanelLoader{api, opt, opt.CacheDir != "", nil}
}

func (l *PanelLoader) Load() (rules []string, err error) {
	return rules, nil
}

func getDB(Type string, loader *PanelLoader) (BlocklistDB, error) {

	var (
		db     BlocklistDB
		err    error
		Format string
	)

	switch Type {
	case "allow":
		Format = loader.opt.AllowlistFormat
	case "block":
		Format = loader.opt.BlocklistFormat
	default:
		return nil, fmt.Errorf("unsupported format '%s'", Format)
	}
	loader.opt.Type = Type

	switch Format {
	case "domainx":
		db, err = NewDomainXDB(Type, loader)
	case "hostsx":
		db, err = NewHostsXDB(Type, loader)
	default:
		return nil, fmt.Errorf("unsupported format '%s'", Format)
	}
	if err != nil {
		return nil, err
	}
	return db, nil
}

func (l *PanelLoader) Get() (RouteDNS *PanelDB, err error) {
	log := Log.WithField("NodeID", l.API.NodeID)
	log.Trace("loading blocklist")

	start := time.Now()

	l.API.NodeType = "Http"
	Nodes, err := l.API.GetNodeInfo()
	if err != nil {
		return nil, err
	}
	l.opt.NodeInfo = Nodes

	var client *socks5.Client
	isdialer := false
	if Nodes.RouteDNS.Socks5.Socks5Address != "" {
		client, err = socks5.NewClient(
			Nodes.RouteDNS.Socks5.Socks5Address,
			Nodes.RouteDNS.Socks5.Username,
			Nodes.RouteDNS.Socks5.Password,
			0,
			int(5*time.Second),
		)
		if err != nil {
			return nil, err
		}
		isdialer = true
	}

	userList, err := l.API.GetUserList()
	if err != nil {
		return nil, err
	}
	l.opt.UserList = userList

	AllowlistDB, err := getDB("allow", l)
	if err != nil {
		return nil, err
	}
	BlocklistDB, err := getDB("block", l)
	if err != nil {
		return nil, err
	}
	IPAllowlistDB, err := NewCidrDBX("iplist", l)
	if err != nil {
		return nil, err
	}

	log.WithField("load-time", time.Since(start)).Trace("completed loading blocklist")

	var Spoof []net.IP
	for _, ip := range Nodes.RouteDNS.Spoof {
		IP := net.ParseIP(ip)
		if ip4 := IP.To4(); len(ip4) == net.IPv4len {
			Spoof = append(Spoof, IP)
		} else if len(ip) == net.IPv6len {
			Spoof = append(Spoof, IP)
		}

		if ip != "" && IP == nil {
			return nil, fmt.Errorf("spoof format error")
		}
	}

	res := &PanelDB{
		Spoof:         Spoof,
		AllowlistDB:   AllowlistDB,
		BlocklistDB:   BlocklistDB,
		IpAllowlistDB: IPAllowlistDB,
	}
	if isdialer {
		res.Socks5Dialer = Socks5Dialer{Client: client, opt: Socks5DialerOptions{
			Username:     Nodes.RouteDNS.Socks5.Username,
			Password:     Nodes.RouteDNS.Socks5.Password,
			TCPTimeout:   0,
			UDPTimeout:   5 * time.Second,
			ResolveLocal: Nodes.RouteDNS.Socks5.ResolveLocal,
			LocalAddr:    net.ParseIP(Nodes.RouteDNS.Socks5.LocalAddr),
		}}
	}
	return res, nil
}

// Loads a cached version of the list from disk. The filename is made by hashing the URL with SHA256
// and the file is expect to be in cache-dir.
func (l *PanelLoader) loadFromDisk() ([]string, error) {
	f, err := os.Open(l.cacheFilename())
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var rules []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		rules = append(rules, scanner.Text())
	}
	return rules, scanner.Err()
}

func (l *PanelLoader) writeToDisk(rules []string) (err error) {
	f, err := ioutil.TempFile(l.opt.CacheDir, "routedns")
	if err != nil {
		return
	}
	fb := bufio.NewWriter(f)

	defer func() {
		tmpFileName := f.Name()
		fb.Flush()
		f.Close() // Close the file before trying to rename (Windows needs it)
		if err == nil {
			err = os.Rename(tmpFileName, l.cacheFilename())
		}
		// Make sure to clean up even if the move above was successful
		os.Remove(tmpFileName)
	}()

	for _, r := range rules {
		if _, err := fb.WriteString(r + "\n"); err != nil {
			return err
		}
	}
	return nil
}

// Returns the name of the list cache file, which is the SHA265 of url in the cache-dir.
func (l *PanelLoader) cacheFilename() string {
	name := fmt.Sprintf("%x", sha256.Sum256([]byte("")))
	return filepath.Join(l.opt.CacheDir, name)
}
