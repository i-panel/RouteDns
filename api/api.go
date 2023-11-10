package api

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	rdns "github.com/folbricht/routedns"
	"github.com/heimdalr/dag"
	"github.com/pion/dtls/v2"
	"github.com/sirupsen/logrus"
)

type Manager struct {
	Enable    bool
	Running   bool
	Listeners []rdns.Listener
	// Map to hold all the resolvers extracted from the config, key'ed by resolver ID. It
	// holds configured resolvers, groups, as well as routers (since they all implement
	// rdns.Resolver)
	Resolvers map[string]rdns.Resolver
	Edges     map[string][]string
	Graph     *dag.DAG
	OnClose   []func()
}

func GetDTLSServerConfig(l *listener) (*dtls.Config, error) {
	cert, key, err := rdns.GetCertFile(&l.Lego)
	if err != nil {
		return nil, err
	}
	return rdns.DTLSServerConfig("", cert, key, l.MutualTLS)
}

func GetTLSServerConfig(l *listener) (*tls.Config, error) {
	cert, key, err := rdns.GetCertFile(&l.Lego)
	if err != nil {
		return nil, err
	}
	return rdns.TLSServerConfig("", cert, key, l.MutualTLS)
}

func GetTLSClientConfig(r *resolver) (*tls.Config, error) {
	cert, key, err := rdns.GetCertFile(&r.Lego)
	if err != nil {
		return nil, err
	}
	return rdns.TLSClientConfig("", cert, key, r.ServerName)
}

func (config *Config) GetPanelManager(logLevel uint32) (*Manager, error) {
	// Set the log level in the library package
	if logLevel > 6 {
		return nil, fmt.Errorf("invalid log level: %d", logLevel)
	}
	if len(config.Listeners) < 1 {
		return nil, errors.New("not enough arguments")
	}

	rdns.Log.SetLevel(logrus.Level(logLevel))

	// Map to hold all the resolvers extracted from the config, key'ed by resolver ID. It
	// holds configured resolvers, groups, as well as routers (since they all implement
	// rdns.Resolver)
	resolvers := make(map[string]rdns.Resolver)

	// See if a bootstrap-resolver was defined in the config. If so, instantiate it,
	// wrap it in a net.Resolver wrapper and replace the net.DefaultResolver with it
	// for all other entities to use.
	if config.BootstrapResolver.Address != "" {
		if err := instantiateResolver("bootstrap-resolver", config.BootstrapResolver, resolvers); err != nil {
			return nil, fmt.Errorf("failed to instantiate bootstrap-resolver: %w", err)
		}
		net.DefaultResolver = rdns.NewNetResolver(resolvers["bootstrap-resolver"])
	}
	// Add all types of nodes to a DAG, this is to find duplicates. Then populate the edges (dependencies).
	graph := dag.NewDAG()
	edges := make(map[string][]string)
	for id, v := range config.Resolvers {
		node := &Node{id, v}
		_, err := graph.AddVertex(node)
		if err != nil {
			return nil, err
		}
	}
	for id, v := range config.Groups {
		node := &Node{id, v}
		_, err := graph.AddVertex(node)
		if err != nil {
			return nil, err
		}
		edges[id] = append(v.Resolvers, v.AllowListResolver, v.BlockListResolver, v.LimitResolver, v.RetryResolver)
	}
	for id, v := range config.Routers {
		node := &Node{id, v}
		_, err := graph.AddVertex(node)
		if err != nil {
			return nil, err
		}
		// One router can have multiple edges to the same resolver.
		// Dedup them before adding to the list of edges.
		dep := make(map[string]struct{})
		for _, route := range v.Routes {
			dep[route.Resolver] = struct{}{}
		}
		for r := range dep {
			edges[id] = append(edges[id], r)
		}
	}
	// Add the edges to the DAG. This will fail if there are duplicate edges, recursion or missing nodes
	for id, es := range edges {
		for _, e := range es {
			if e == "" {
				continue
			}
			if err := graph.AddEdge(id, e); err != nil {
				return nil, err
			}
		}
	}

	// Instantiate the elements from leaves to the root nodes
	for graph.GetOrder() > 0 {
		leaves := graph.GetLeaves()
		var pgm []string
		for id, v := range leaves {
			node := v.(*Node)
			if g, ok := node.value.(group); ok {
				if g.Type == "blocklist-panel" {
					pgm = append(pgm, id)
					break
				}
			}
		}
		if len(pgm) > 0 {
			var pm []group
			for _, v := range leaves {
				node := v.(*Node)
				if g, ok := node.value.(group); ok {
					if g.Type == "panel-rotate" {
						pm = append(pm, g)
					}
				}
			}
			if len(pm) == 0 {
				return nil, fmt.Errorf("%d blocklist-panel found but panel-rotate not found", len(pgm))
			} else if len(pm) > 1 {
				return nil, fmt.Errorf("currently only one panel-rotate is supported, found %d", len(pgm))
			}
		}

		

		for id, v := range leaves {
			node := v.(*Node)
			if r, ok := node.value.(resolver); ok {
				if err := instantiateResolver(id, r, resolvers); err != nil {
					return nil, err
				}
			}
			if g, ok := node.value.(group); ok {
				if err := instantiateGroup(id, g, resolvers, pgm); err != nil {
					return nil, err
				}
			}
			if r, ok := node.value.(router); ok {
				if err := instantiateRouter(id, r, resolvers); err != nil {
					return nil, err
				}
			}
			if err := graph.DeleteVertex(id); err != nil {
				return nil, err
			}
		}
	}

	// Build the Listeners last as they can point to routers, groups or resolvers directly.
	var listeners []rdns.Listener
	for id, l := range config.Listeners {
		resolver, ok := resolvers[l.Resolver]
		// All Listeners should route queries (except the admin service).
		if !ok && l.Protocol != "admin" {
			return nil, fmt.Errorf("listener '%s' references non-existent resolver, group or router '%s'", id, l.Resolver)
		}
		allowedNet, err := parseCIDRList(l.AllowedNet)
		if err != nil {
			return nil, err
		}

		opt := rdns.ListenOptions{AllowedNet: allowedNet}

		switch l.Protocol {
		case "tcp":
			l.Address = rdns.AddressWithDefault(l.Address, rdns.PlainDNSPort)
			listeners = append(listeners, rdns.NewDNSListener(id, l.Address, "tcp", opt, resolver))
		case "udp":
			l.Address = rdns.AddressWithDefault(l.Address, rdns.PlainDNSPort)
			listeners = append(listeners, rdns.NewDNSListener(id, l.Address, "udp", opt, resolver))
		case "admin":
			tlsConfig, err := GetTLSServerConfig(&l)
			// tlsConfig, err := rdns.TLSServerConfig(l.CA, l.ServerCrt, l.ServerKey, l.MutualTLS)
			if err != nil {
				return nil, err
			}
			opt := rdns.AdminListenerOptions{
				TLSConfig:     tlsConfig,
				ListenOptions: opt,
				Transport:     l.Transport,
			}
			ln, err := rdns.NewAdminListener(id, l.Address, opt)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, ln)
		case "dot":
			l.Address = rdns.AddressWithDefault(l.Address, rdns.DoTPort)
			tlsConfig, err := GetTLSServerConfig(&l)
			if err != nil {
				return nil, err
			}
			ln := rdns.NewDoTListener(id, l.Address, rdns.DoTListenerOptions{TLSConfig: tlsConfig, ListenOptions: opt}, resolver)
			listeners = append(listeners, ln)
		case "dtls":
			l.Address = rdns.AddressWithDefault(l.Address, rdns.DTLSPort)
			dtlsConfig, err := GetDTLSServerConfig(&l)
			if err != nil {
				return nil, err
			}
			ln := rdns.NewDTLSListener(id, l.Address, rdns.DTLSListenerOptions{DTLSConfig: dtlsConfig, ListenOptions: opt}, resolver)
			listeners = append(listeners, ln)
		case "doh":
			if l.Transport != "quic" {
				l.Address = rdns.AddressWithDefault(l.Address, rdns.DoHPort)
			} else if l.Transport == "quic" {
				l.Address = rdns.AddressWithDefault(l.Address, rdns.DohQuicPort)
			}
			var tlsConfig *tls.Config
			if l.NoTLS {
				if l.Transport == "quic" {
					return nil, errors.New("no-tls is not supported for doh servers with quic transport")
				}
			} else {
				fmt.Println("p4")
				tlsConfig, err = GetTLSServerConfig(&l)
				if err != nil {
					return nil, err
				}
			}
			var httpProxyNet *net.IPNet
			if l.Frontend.HTTPProxyNet != "" {
				_, httpProxyNet, err = net.ParseCIDR(l.Frontend.HTTPProxyNet)
				if err != nil {
					return nil, fmt.Errorf("listener '%s' trusted-proxy '%s': %v", id, l.Frontend.HTTPProxyNet, err)
				}
			}
			opt := rdns.DoHListenerOptions{
				TLSConfig:     tlsConfig,
				ListenOptions: opt,
				Transport:     l.Transport,
				HTTPProxyNet:  httpProxyNet,
				NoTLS:         l.NoTLS,
			}
			ln, err := rdns.NewDoHListener(id, l.Address, opt, resolver)
			if err != nil {
				return nil, err
			}
			listeners = append(listeners, ln)
		case "doq":
			l.Address = rdns.AddressWithDefault(l.Address, rdns.DoQPort)

			tlsConfig, err := GetTLSServerConfig(&l)
			if err != nil {
				return nil, err
			}
			ln := rdns.NewQUICListener(id, l.Address, rdns.DoQListenerOptions{TLSConfig: tlsConfig, ListenOptions: opt}, resolver)
			listeners = append(listeners, ln)
		default:
			return nil, fmt.Errorf("unsupported protocol '%s' for listener '%s'", l.Protocol, id)
		}
	}

	return &Manager{
		Running:   false,
		Listeners: listeners,
		Resolvers: resolvers,
		Graph:     graph,
		Edges:     edges,
		OnClose:   onClose,
	}, nil
}

func (m *Manager) Close() error {
	rdns.Log.Info("stopping")
	for _, f := range m.OnClose {
		f()
	}
	for _, listener := range m.Listeners {
		err := listener.Stop()
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Start() error {
	// Start the listeners
	for _, l := range m.Listeners {
		go func(l rdns.Listener) error {
			err := l.Start()
			if err != nil {
				return err
			}
			rdns.Log.WithError(err).Error("listener failed")
			time.Sleep(time.Second)
			return nil
		}(l)
	}
	m.Running = true
	return nil
}