package api

import (
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"time"

	syslog "github.com/RackSec/srslog"
	"github.com/XrayR-project/XrayR/api/sspanel"
	rdns "github.com/folbricht/routedns"
	"github.com/heimdalr/dag"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

type options struct {
	logLevel uint32
	version  bool
}

type Node struct {
	id    string
	value interface{}
}

var _ dag.IDInterface = Node{}

func (n Node) ID() string {
	return n.id
}

// Functions to call on shutdown
var onClose []func()



// Instantiate a group object based on configuration and add to the map of resolvers by ID.
func instantiateGroup(id string, g group, resolvers map[string]rdns.Resolver) error {
	var gr []rdns.Resolver
	var err error
	for _, rid := range g.Resolvers {
		resolver, ok := resolvers[rid]
		if !ok {
			return fmt.Errorf("group '%s' references non-existent resolver or group '%s'", id, rid)
		}
		gr = append(gr, resolver)
	}
	switch g.Type {
	case "round-robin":
		resolvers[id] = rdns.NewRoundRobin(id, gr...)
	case "fail-rotate":
		opt := rdns.FailRotateOptions{
			ServfailError: g.ServfailError,
		}
		resolvers[id] = rdns.NewFailRotate(id, opt, gr...)
	case "fail-back":
		opt := rdns.FailBackOptions{
			ResetAfter:    time.Duration(time.Duration(g.ResetAfter) * time.Second),
			ServfailError: g.ServfailError,
		}
		resolvers[id] = rdns.NewFailBack(id, opt, gr...)
	case "panel-rotate":
		if len(gr) != 1 {
			return fmt.Errorf("type panel-rotate only supports one resolver in '%s'", id)
		}
		resolvers[id] = rdns.NewPanelRotate(id, gr[0])
	case "fastest":
		resolvers[id] = rdns.NewFastest(id, gr...)
	case "random":
		opt := rdns.RandomOptions{
			ResetAfter:    time.Duration(time.Duration(g.ResetAfter) * time.Second),
			ServfailError: g.ServfailError,
		}
		resolvers[id] = rdns.NewRandom(id, opt, gr...)
	case "blocklist":
		if len(gr) != 1 {
			return fmt.Errorf("type blocklist only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && g.Source != "" {
			return fmt.Errorf("static blocklist can't be used with 'source' in '%s'", id)
		}
		blocklistDB, err := newBlocklistDB(list{Name: id, Format: g.Format, Source: g.Source}, g.Blocklist)
		if err != nil {
			return err
		}
		opt := rdns.BlocklistOptions{
			BlocklistDB:      blocklistDB,
			BlocklistRefresh: time.Duration(g.Refresh) * time.Second,
		}
		resolvers[id], err = rdns.NewBlocklist(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "blocklist-v2":
		if len(gr) != 1 {
			return fmt.Errorf("type blocklist-v2 only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && len(g.BlocklistSource) > 0 {
			return fmt.Errorf("static blocklist can't be used with 'source' in '%s'", id)
		}
		if len(g.Allowlist) > 0 && len(g.AllowlistSource) > 0 {
			return fmt.Errorf("static allowlist can't be used with 'source' in '%s'", id)
		}
		var blocklistDB rdns.BlocklistDB
		if len(g.Blocklist) > 0 {
			blocklistDB, err = newBlocklistDB(list{Name: id, Format: g.BlocklistFormat}, g.Blocklist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.BlocklistDB
			for _, s := range g.BlocklistSource {
				db, err := newBlocklistDB(s, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			blocklistDB, err = rdns.NewMultiDB(dbs...)
			if err != nil {
				return err
			}
		}
		var allowlistDB rdns.BlocklistDB
		if len(g.Allowlist) > 0 {
			allowlistDB, err = newBlocklistDB(list{Format: g.AllowlistFormat}, g.Allowlist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.BlocklistDB
			for _, s := range g.AllowlistSource {
				db, err := newBlocklistDB(s, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			allowlistDB, err = rdns.NewMultiDB(dbs...)
			if err != nil {
				return err
			}
		}
		opt := rdns.BlocklistOptions{
			BlocklistResolver: resolvers[g.BlockListResolver],
			BlocklistDB:       blocklistDB,
			BlocklistRefresh:  time.Duration(g.BlocklistRefresh) * time.Second,
			AllowListResolver: resolvers[g.AllowListResolver],
			AllowlistDB:       allowlistDB,
			AllowlistRefresh:  time.Duration(g.AllowlistRefresh) * time.Second,
		}
		resolvers[id], err = rdns.NewBlocklist(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "blocklist-panel":
		if len(gr) != 1 {
			return fmt.Errorf("type blocklist-panel only supports one resolver in '%s'", id)
		}

		// if len(g.Allowlist) == 0 {
		// 	return fmt.Errorf("type blocklist-panel only supports one resolver in '%s'", id)
		// }

		ApiClient := sspanel.New(&g.Panel)
		loader := rdns.NewPanelLoader(ApiClient, rdns.PanelLoaderOptions{
			AllowlistFormat: g.AllowlistFormat,
			BlocklistFormat: g.BlocklistFormat,
		})
		panelDB, err := loader.Get()
		if err != nil {
			return err
		}

		opt := rdns.PanellistOptions{
			Loader:              loader,
			Refresh:             time.Duration(g.PanelRefresh) * time.Minute,
			DB:                  panelDB,
			AllowListResolver:   resolvers[g.AllowListResolver],
			BlockListResolver:   resolvers[g.BlockListResolver],
			IpAllowListResolver: resolvers[g.IpAllowListResolver],
		}
		resolvers[id], err = rdns.NewPanellist(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "replace":
		if len(gr) != 1 {
			return fmt.Errorf("type replace only supports one resolver in '%s'", id)
		}
		resolvers[id], err = rdns.NewReplace(id, gr[0], g.Replace...)
		if err != nil {
			return err
		}
	case "ttl-modifier":
		if len(gr) != 1 {
			return fmt.Errorf("type ttl-modifier only supports one resolver in '%s'", id)
		}
		var selectFunc rdns.TTLSelectFunc
		switch g.TTLSelect {
		case "lowest":
			selectFunc = rdns.TTLSelectLowest
		case "highest":
			selectFunc = rdns.TTLSelectHighest
		case "average":
			selectFunc = rdns.TTLSelectAverage
		case "first":
			selectFunc = rdns.TTLSelectFirst
		case "last":
			selectFunc = rdns.TTLSelectLast
		case "random":
			selectFunc = rdns.TTLSelectRandom
		case "":
		default:
			return fmt.Errorf("invalid ttl-select value: %q", g.TTLSelect)
		}
		opt := rdns.TTLModifierOptions{
			SelectFunc: selectFunc,
			MinTTL:     g.TTLMin,
			MaxTTL:     g.TTLMax,
		}
		resolvers[id] = rdns.NewTTLModifier(id, gr[0], opt)
	case "truncate-retry":
		if len(gr) != 1 {
			return fmt.Errorf("type truncate-retry only supports one resolver in '%s'", id)
		}
		retryResolver := resolvers[g.RetryResolver]
		if retryResolver == nil {
			return errors.New("type truncate-retry requires 'retry-resolver' option")
		}
		opt := rdns.TruncateRetryOptions{}
		resolvers[id] = rdns.NewTruncateRetry(id, gr[0], retryResolver, opt)
	case "request-dedup":
		if len(gr) != 1 {
			return fmt.Errorf("type request-dedup only supports one resolver in '%s'", id)
		}
		resolvers[id] = rdns.NewRequestDedup(id, gr[0])
	case "fastest-tcp":
		if len(gr) != 1 {
			return fmt.Errorf("type fastest-tcp only supports one resolver in '%s'", id)
		}
		opt := rdns.FastestTCPOptions{
			Port:          g.Port,
			WaitAll:       g.WaitAll,
			SuccessTTLMin: g.SuccessTTLMin,
		}
		resolvers[id] = rdns.NewFastestTCP(id, gr[0], opt)
	case "ecs-modifier":
		if len(gr) != 1 {
			return fmt.Errorf("type ecs-modifier only supports one resolver in '%s'", id)
		}
		var f rdns.ECSModifierFunc
		switch g.ECSOp {
		case "add":
			f = rdns.ECSModifierAdd(g.ECSAddress, g.ECSPrefix4, g.ECSPrefix6)
		case "delete":
			f = rdns.ECSModifierDelete
		case "privacy":
			f = rdns.ECSModifierPrivacy(g.ECSPrefix4, g.ECSPrefix6)
		case "":
		default:
			return fmt.Errorf("unsupported ecs-modifier operation '%s'", g.ECSOp)
		}
		resolvers[id], err = rdns.NewECSModifier(id, gr[0], f)
		if err != nil {
			return err
		}
	case "edns0-modifier":
		if len(gr) != 1 {
			return fmt.Errorf("type edns0-modifier only supports one resolver in '%s'", id)
		}
		var f rdns.EDNS0ModifierFunc
		switch g.EDNS0Op {
		case "add":
			f = rdns.EDNS0ModifierAdd(g.EDNS0Code, g.EDNS0Data)
		case "delete":
			f = rdns.EDNS0ModifierDelete(g.EDNS0Code)
		case "":
		default:
			return fmt.Errorf("unsupported edns0-modifier operation '%s'", g.EDNS0Op)
		}
		resolvers[id], err = rdns.NewEDNS0Modifier(id, gr[0], f)
		if err != nil {
			return err
		}
	case "syslog":
		if len(gr) != 1 {
			return fmt.Errorf("type syslog only supports one resolver in '%s'", id)
		}
		var priority int
		switch g.Priority {
		case "emergency", "":
			priority = int(syslog.LOG_EMERG)
		case "alert":
			priority = int(syslog.LOG_ALERT)
		case "critical":
			priority = int(syslog.LOG_CRIT)
		case "error":
			priority = int(syslog.LOG_ERR)
		case "warning":
			priority = int(syslog.LOG_WARNING)
		case "notice":
			priority = int(syslog.LOG_NOTICE)
		case "info":
			priority = int(syslog.LOG_INFO)
		case "debug":
			priority = int(syslog.LOG_DEBUG)
		default:
			return fmt.Errorf("unsupported syslog priority %q", g.Priority)
		}
		opt := rdns.SyslogOptions{
			Network:     g.Network,
			Address:     g.Address,
			Priority:    priority,
			Tag:         g.Tag,
			LogRequest:  g.LogRequest,
			LogResponse: g.LogResponse,
			Verbose:     g.Verbose,
		}
		resolvers[id] = rdns.NewSyslog(id, gr[0], opt)
	case "cache":
		var shuffleFunc rdns.AnswerShuffleFunc
		switch g.CacheAnswerShuffle {
		case "": // default
		case "random":
			shuffleFunc = rdns.AnswerShuffleRandom
		case "round-robin":
			shuffleFunc = rdns.AnswerShuffleRoundRobin
		default:
			return fmt.Errorf("unsupported shuffle function %q", g.CacheAnswerShuffle)
		}

		cacheRcodeMaxTTL := make(map[int]uint32)
		for k, v := range g.CacheRcodeMaxTTL {
			code, err := strconv.Atoi(k)
			if err != nil {
				return fmt.Errorf("failed to decode key in cache-rcode-max-ttl: %w", err)
			}
			cacheRcodeMaxTTL[code] = v
		}

		opt := rdns.CacheOptions{
			GCPeriod:            time.Duration(g.GCPeriod) * time.Second,
			Capacity:            g.CacheSize,
			NegativeTTL:         g.CacheNegativeTTL,
			CacheRcodeMaxTTL:    cacheRcodeMaxTTL,
			ShuffleAnswerFunc:   shuffleFunc,
			HardenBelowNXDOMAIN: g.CacheHardenBelowNXDOMAIN,
			FlushQuery:          g.CacheFlushQuery,
			PrefetchTrigger:     g.PrefetchTrigger,
			PrefetchEligible:    g.PrefetchEligible,
		}
		if g.Backend != nil {
			var backend rdns.CacheBackend
			switch g.Backend.Type {
			case "memory":
				backend = rdns.NewMemoryBackend(rdns.MemoryBackendOptions{
					Capacity:     g.Backend.Size,
					GCPeriod:     time.Duration(g.Backend.GCPeriod) * time.Second,
					Filename:     g.Backend.Filename,
					SaveInterval: time.Duration(g.Backend.SaveInterval) * time.Second,
				})
				onClose = append(onClose, func() { backend.Close() })
			case "redis":
				minRetryBackoff := time.Duration(g.Backend.RedisMinRetryBackoff) * time.Millisecond
				if g.Backend.RedisMinRetryBackoff == -1 {
					minRetryBackoff = -1
				}
				maxRetryBackoff := time.Duration(g.Backend.RedisMaxRetryBackoff) * time.Millisecond
				if g.Backend.RedisMaxRetryBackoff == -1 {
					maxRetryBackoff = -1
				}
				backend = rdns.NewRedisBackend(rdns.RedisBackendOptions{
					RedisOptions: redis.Options{
						Network:               g.Backend.RedisNetwork,
						Addr:                  g.Backend.RedisAddress,
						Username:              g.Backend.RedisUsername,
						Password:              g.Backend.RedisPassword,
						DB:                    g.Backend.RedisDB,
						ContextTimeoutEnabled: true,
						MaxRetries:            g.Backend.RedisMaxRetries,
						MinRetryBackoff:       minRetryBackoff,
						MaxRetryBackoff:       maxRetryBackoff,
					},
					KeyPrefix: g.Backend.RedisKeyPrefix,
				})
			default:
				return fmt.Errorf("unsupported cache backend %q", g.Backend.Type)
			}
			opt.Backend = backend
		}
		resolvers[id] = rdns.NewCache(id, gr[0], opt)
	case "response-blocklist-ip", "response-blocklist-cidr": // "response-blocklist-cidr" has been retired/renamed to "response-blocklist-ip"
		if len(gr) != 1 {
			return fmt.Errorf("type response-blocklist-ip only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && len(g.BlocklistSource) > 0 {
			return fmt.Errorf("static blocklist can't be used with 'blocklist-source' in '%s'", id)
		}
		var blocklistDB rdns.IPBlocklistDB
		if len(g.Blocklist) > 0 {
			blocklistDB, err = newIPBlocklistDB(list{Name: id, Format: g.BlocklistFormat}, g.LocationDB, g.Blocklist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.IPBlocklistDB
			for _, s := range g.BlocklistSource {
				db, err := newIPBlocklistDB(s, g.LocationDB, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			blocklistDB, err = rdns.NewMultiIPDB(dbs...)
			if err != nil {
				return err
			}
		}
		opt := rdns.ResponseBlocklistIPOptions{
			BlocklistResolver: resolvers[g.BlockListResolver],
			BlocklistDB:       blocklistDB,
			BlocklistRefresh:  time.Duration(g.BlocklistRefresh) * time.Second,
			Filter:            g.Filter,
			Inverted:          g.Inverted,
		}
		resolvers[id], err = rdns.NewResponseBlocklistIP(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "response-blocklist-name":
		if len(gr) != 1 {
			return fmt.Errorf("type response-blocklist-name only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && len(g.BlocklistSource) > 0 {
			return fmt.Errorf("static blocklist can't be used with 'blocklist-source' in '%s'", id)
		}
		var blocklistDB rdns.BlocklistDB
		if len(g.Blocklist) > 0 {
			blocklistDB, err = newBlocklistDB(list{Format: g.BlocklistFormat}, g.Blocklist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.BlocklistDB
			for _, s := range g.BlocklistSource {
				db, err := newBlocklistDB(s, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			blocklistDB, err = rdns.NewMultiDB(dbs...)
			if err != nil {
				return err
			}
		}
		opt := rdns.ResponseBlocklistNameOptions{
			BlocklistResolver: resolvers[g.BlockListResolver],
			BlocklistDB:       blocklistDB,
			BlocklistRefresh:  time.Duration(g.BlocklistRefresh) * time.Second,
			Inverted:          g.Inverted,
		}
		resolvers[id], err = rdns.NewResponseBlocklistName(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "client-allowlist":
		if len(gr) != 1 {
			return fmt.Errorf("type client-allowlist only supports one resolver in '%s'", id)
		}
		if len(g.Allowlist) > 0 && len(g.AllowlistSource) > 0 {
			return fmt.Errorf("static allowlist can't be used with 'allowlist-source' in '%s'", id)
		}
		var allowlistDB rdns.IPBlocklistDB
		if len(g.Allowlist) > 0 {
			allowlistDB, err = newIPBlocklistDB(list{Name: id, Format: g.AllowlistFormat}, g.LocationDB, g.Allowlist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.IPBlocklistDB
			for _, s := range g.AllowlistSource {
				db, err := newIPBlocklistDB(s, g.LocationDB, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			allowlistDB, err = rdns.NewMultiIPDB(dbs...)
			if err != nil {
				return err
			}
		}
		opt := rdns.ClientAllowlistOptions{
			AllowlistResolver: resolvers[g.AllowListResolver],
			AllowlistDB:       allowlistDB,
			AllowlistRefresh:  time.Duration(g.AllowlistRefresh) * time.Second,
			AllowRemote:       g.AllowRemoteIpDB,
		}
		resolvers[id], err = rdns.NewClientAllowlist(id, gr[0], opt)
		if err != nil {
			return err
		}
	case "client-blocklist":
		if len(gr) != 1 {
			return fmt.Errorf("type client-blocklist only supports one resolver in '%s'", id)
		}
		if len(g.Blocklist) > 0 && len(g.BlocklistSource) > 0 {
			return fmt.Errorf("static blocklist can't be used with 'blocklist-source' in '%s'", id)
		}
		var blocklistDB rdns.IPBlocklistDB
		if len(g.Blocklist) > 0 {
			blocklistDB, err = newIPBlocklistDB(list{Name: id, Format: g.BlocklistFormat}, g.LocationDB, g.Blocklist)
			if err != nil {
				return err
			}
		} else {
			var dbs []rdns.IPBlocklistDB
			for _, s := range g.BlocklistSource {
				db, err := newIPBlocklistDB(s, g.LocationDB, nil)
				if err != nil {
					return fmt.Errorf("%s: %w", id, err)
				}
				dbs = append(dbs, db)
			}
			blocklistDB, err = rdns.NewMultiIPDB(dbs...)
			if err != nil {
				return err
			}
		}
		opt := rdns.ClientBlocklistOptions{
			BlocklistResolver: resolvers[g.BlockListResolver],
			BlocklistDB:       blocklistDB,
			BlocklistRefresh:  time.Duration(g.BlocklistRefresh) * time.Second,
			AllowRemote:       g.AllowRemoteIpDB,
		}
		resolvers[id], err = rdns.NewClientBlocklist(id, gr[0], opt)
		if err != nil {
			return err
		}

	case "static-responder":
		var edns0Options []dns.EDNS0
		if g.EDNS0EDE != nil {
			edns0Options = append(edns0Options, &dns.EDNS0_EDE{
				InfoCode:  g.EDNS0EDE.Code,
				ExtraText: g.EDNS0EDE.Text,
			})
		}
		opt := rdns.StaticResolverOptions{
			Answer:       g.Answer,
			NS:           g.NS,
			Extra:        g.Extra,
			RCode:        g.RCode,
			Truncate:     g.Truncate,
			EDNS0Options: edns0Options,
		}
		resolvers[id], err = rdns.NewStaticResolver(id, opt)
		if err != nil {
			return err
		}
	case "response-minimize":
		if len(gr) != 1 {
			return fmt.Errorf("type response-minimize only supports one resolver in '%s'", id)
		}
		resolvers[id] = rdns.NewResponseMinimize(id, gr[0])
	case "response-collapse":
		if len(gr) != 1 {
			return fmt.Errorf("type response-collapse only supports one resolver in '%s'", id)
		}
		opt := rdns.ResponseCollapseOptions{
			NullRCode: g.NullRCode,
		}
		resolvers[id] = rdns.NewResponseCollapse(id, gr[0], opt)
	case "drop":
		resolvers[id] = rdns.NewDropResolver(id)
	case "rate-limiter":
		if len(gr) != 1 {
			return fmt.Errorf("type rate-limiter only supports one resolver in '%s'", id)
		}
		opt := rdns.RateLimiterOptions{
			Requests:      g.Requests,
			Window:        g.Window,
			Prefix4:       g.Prefix4,
			Prefix6:       g.Prefix6,
			LimitResolver: resolvers[g.LimitResolver],
		}
		resolvers[id] = rdns.NewRateLimiter(id, gr[0], opt)

	default:
		return fmt.Errorf("unsupported group type '%s' for group '%s'", g.Type, id)
	}
	return nil
}

// Instantiate a router object based on configuration and add to the map of resolvers by ID.
func instantiateRouter(id string, r router, resolvers map[string]rdns.Resolver) error {
	router := rdns.NewRouter(id)
	for _, route := range r.Routes {
		resolver, ok := resolvers[route.Resolver]
		if !ok {
			return fmt.Errorf("router '%s' references non-existent resolver or group '%s'", id, route.Resolver)
		}
		types := route.Types
		if route.Type != "" { // Support the deprecated "Type" by just adding it to "Types" if defined
			types = append(types, route.Type)
		}
		r, err := rdns.NewRoute(route.Name, route.Class, types, route.Weekdays, route.Before, route.After, route.Source, route.DoHPath, route.Listener, route.TLSServerName, resolver)
		if err != nil {
			return fmt.Errorf("failure parsing routes for router '%s' : %s", id, err.Error())
		}
		r.Invert(route.Invert)
		router.Add(r)
	}
	resolvers[id] = router
	return nil
}

func newBlocklistDB(l list, rules []string) (rdns.BlocklistDB, error) {
	loc, err := url.Parse(l.Source)
	if err != nil {
		return nil, err
	}
	name := l.Name
	if name == "" {
		name = l.Source
	}
	var loader rdns.BlocklistLoader
	if len(rules) > 0 {
		loader = rdns.NewStaticLoader(rules)
	} else {
		switch loc.Scheme {
		case "http", "https":
			opt := rdns.HTTPLoaderOptions{
				CacheDir:     l.CacheDir,
				AllowFailure: l.AllowFailure,
			}
			loader = rdns.NewHTTPLoader(l.Source, opt)
		case "":
			opt := rdns.FileLoaderOptions{
				AllowFailure: l.AllowFailure,
			}
			loader = rdns.NewFileLoader(l.Source, opt)
		default:
			return nil, fmt.Errorf("unsupported scheme '%s' in '%s'", loc.Scheme, l.Source)
		}
	}
	switch l.Format {
	case "regexp", "":
		return rdns.NewRegexpDB(name, loader)
	case "domain":
		return rdns.NewDomainDB(name, loader)
	case "hosts":
		return rdns.NewHostsDB(name, loader)
	default:
		return nil, fmt.Errorf("unsupported format '%s'", l.Format)
	}
}

func newIPBlocklistDB(l list, locationDB string, rules []string) (rdns.IPBlocklistDB, error) {
	loc, err := url.Parse(l.Source)
	if err != nil {
		return nil, err
	}
	name := l.Name
	if name == "" {
		name = l.Source
	}
	var loader rdns.BlocklistLoader
	if len(rules) > 0 {
		loader = rdns.NewStaticLoader(rules)
	} else {
		switch loc.Scheme {
		case "http", "https":
			opt := rdns.HTTPLoaderOptions{
				CacheDir:     l.CacheDir,
				AllowFailure: l.AllowFailure,
			}
			loader = rdns.NewHTTPLoader(l.Source, opt)
		case "":
			opt := rdns.FileLoaderOptions{
				AllowFailure: l.AllowFailure,
			}
			loader = rdns.NewFileLoader(l.Source, opt)
		default:
			return nil, fmt.Errorf("unsupported scheme '%s' in '%s'", loc.Scheme, l.Source)
		}
	}

	switch l.Format {
	case "cidr", "":
		return rdns.NewCidrDB(name, loader)
	case "location":
		return rdns.NewGeoIPDB(name, loader, locationDB)
	default:
		return nil, fmt.Errorf("unsupported format '%s'", l.Format)
	}
}

func printVersion() {
	fmt.Println("Build: ", rdns.BuildNumber)
	fmt.Println("Build Time: ", rdns.BuildTime)
	fmt.Println("Version: ", rdns.BuildVersion)
}
