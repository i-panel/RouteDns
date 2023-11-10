package rdns

import (
	"bufio"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/XrayR-project/XrayR/api"
	"github.com/XrayR-project/XrayR/api/sspanel"
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
	CacheDir string
	BlocklistFormat string
	AllowlistFormat string
	NodeInfo      *api.NodeInfo
	UserList      *[]api.UserInfo
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

func getDB(name, Type string, loader *PanelLoader) (BlocklistDB, error) {

	var (
		db  BlocklistDB
		err error
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
	loader.opt.Type =Type
	
	switch Format {
	case "domainx":
		db, err = NewDomainXDB(name, loader)
	case "hostsx":
		db, err = NewHostsXDB(name, loader)
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
	if err !=nil {
		return nil, err
	}
	l.opt.NodeInfo = Nodes

	userList, err := l.API.GetUserList()
	if err !=nil {
		return nil, err
	}
	l.opt.UserList = userList

	AllowlistDB, err := getDB("name-here", "allow", l)
	if err != nil {
		return nil, err
	}
	BlocklistDB, err := getDB("name-here", "block", l)
	if err != nil {
		return nil, err
	}
	IPAllowlistDB, err := NewCidrDBX("name-here", l)
	if err != nil {
		return nil, err
	}

	log.WithField("load-time", time.Since(start)).Trace("completed loading blocklist")

	return &PanelDB{
		AllowlistDB:   AllowlistDB,
		BlocklistDB:   BlocklistDB,
		IpAllowlistDB: IPAllowlistDB,
	}, nil
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
