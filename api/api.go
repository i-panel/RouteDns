package api

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	rdns "github.com/folbricht/routedns"
	"github.com/heimdalr/dag"
	"github.com/pion/dtls/v2"
	"github.com/sirupsen/logrus"
	"github.com/xtls/xray-core/common/task"
)

type periodicTask struct {
	Tag string
	*task.Periodic
}

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
	Tasks     []periodicTask
}

func GetDTLSServerConfig(l *listener) (*dtls.Config, error) {
	cert, key, ca, err := rdns.GetCertFile(&l.Lego)
	if err != nil {
		return nil, err
	}
	return rdns.DTLSServerConfig(ca, cert, key, l.MutualTLS)
}

func GetTLSServerConfig(l *listener) (*tls.Config, error) {
	cert, key, ca, err := rdns.GetCertFile(&l.Lego)
	if err != nil {
		return nil, err
	}
	return rdns.TLSServerConfig(ca, cert, key, l.MutualTLS)
}

func GetTLSClientConfig(r *resolver) (*tls.Config, error) {
	cert, key, ca, err := rdns.GetCertFile(&r.Lego)
	if err != nil {
		return nil, err
	}
	return rdns.TLSClientConfig(ca, cert, key, r.ServerName)
}

func (config *Config) GetPanelManager(logLevel uint32) (*Manager, error) {
	// Set the log level in the library package
	if logLevel > 6 {
		return nil, fmt.Errorf("invalid log level: %d", logLevel)
	}
	if len(config.Listeners) < 1 {
		return nil, errors.New("not enough arguments")
	}

	pwd, wdErr := os.Getwd()
	if wdErr != nil {
		return nil, fmt.Errorf("can not get current working directory")
	}

	err := os.Setenv("XRAY_LOCATION_ASSET", pwd)
	if err != nil {
		return nil, fmt.Errorf("could not set asset working directory., error: %s", err)
	}

	rdns.Log.SetLevel(logrus.Level(logLevel))

	// Map to hold all the resolvers extracted from the config, key'ed by resolver ID. It
	// holds configured resolvers, groups, as well as routers (since they all implement
	// rdns.Resolver)
	resolvers := make(map[string]rdns.Resolver)
	var tasks []periodicTask

	// See if a bootstrap-resolver was defined in the config. If so, instantiate it,
	// wrap it in a net.Resolver wrapper and replace the net.DefaultResolver with it
	// for all other entities to use.
	if config.BootstrapResolver.Address != "" {
		if err := instantiateResolver("bootstrap-resolver", config.BootstrapResolver, resolvers); err != nil {
			return nil, fmt.Errorf("failed to instantiate bootstrap-resolver: %w", err)
		}
		net.DefaultResolver = rdns.NewNetResolver(resolvers["bootstrap-resolver"])
		if config.BootstrapResolver.Lego.CertMode != "" && config.BootstrapResolver.Lego.CertMode != "none" {
			tasks = append(tasks, periodicTask{
				Tag: "cert monitor",
				Periodic: &task.Periodic{
					Interval: time.Duration(config.BootstrapResolver.Lego.UpdatePeriodic) * time.Second * 60,
					Execute:  resolvers["bootstrap-resolver"].CertMonitor,
				}})
		}
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

	var pgm []string
	var pm []string
	for id, v := range config.Groups {
		node := &Node{id, v}
		if v.Type == "blocklist-panel" {
			pgm = append(pgm, id)
		}
		if v.Type == "panel-rotate" {
			pm = append(pm, id)
		}
		_, err := graph.AddVertex(node)
		if err != nil {
			return nil, err
		}
		edges[id] = append(v.Resolvers, v.AllowListResolver, v.BlockListResolver, v.LimitResolver, v.RetryResolver)
	}

	if len(pgm) > 0 && len(pm) == 0 {
		return nil, fmt.Errorf("%d blocklist-panel found but panel-rotate not found", len(pgm))
	} else if len(pgm) > 0 && len(pm) > 1 {
		return nil, fmt.Errorf("currently only one panel-rotate is supported, found %d", len(pgm))
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
		for id, v := range leaves {
			node := v.(*Node)
			if r, ok := node.value.(resolver); ok {
				if err := instantiateResolver(id, r, resolvers); err != nil {
					return nil, err
				}
				if r.Lego.CertMode != "" && r.Lego.CertMode != "none" {
					tasks = append(tasks, periodicTask{
						Tag: "cert monitor",
						Periodic: &task.Periodic{
							Interval: time.Duration(r.Lego.UpdatePeriodic) * time.Second * 60,
							Execute:  resolvers[id].CertMonitor,
						}})
				}
			}
			if g, ok := node.value.(group); ok {
				if err := instantiateGroup(id, g, resolvers); err != nil {
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
	if len(pgm) > 0 && len(pm) > 0 {
		if pr, ok := resolvers[pm[0]].(*rdns.PanelRotate); ok {
			for id := range pgm {
				pr.PanelResolvers = append(pr.PanelResolvers, resolvers[pgm[id]])
				delete(resolvers, pgm[id])
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
			listener := rdns.NewDNSListener(id, l.Address, "tcp", opt, resolver)
			listeners = append(listeners, listener)
			if l.Lego.CertMode != "" && l.Lego.CertMode != "none" {
				tasks = append(tasks, periodicTask{
					Tag: "cert monitor",
					Periodic: &task.Periodic{
						Interval: time.Duration(l.Lego.UpdatePeriodic) * time.Second * 60,
						Execute:  listener.CertMonitor,
					},
				})
			}
			
		case "udp":
			l.Address = rdns.AddressWithDefault(l.Address, rdns.PlainDNSPort)
			listener := rdns.NewDNSListener(id, l.Address, "udp", opt, resolver)
			listeners = append(listeners, listener)
			if l.Lego.CertMode != "" && l.Lego.CertMode != "none" {
				tasks = append(tasks, periodicTask{
					Tag: "cert monitor",
					Periodic: &task.Periodic{
						Interval: time.Duration(l.Lego.UpdatePeriodic) * time.Second * 60,
						Execute:  listener.CertMonitor,
					},
				})
			}
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
			ln.Lego = &l.Lego
			ln.MutualTLS = l.MutualTLS
			listeners = append(listeners, ln)
			if l.Lego.CertMode != "" && l.Lego.CertMode != "none" {
				tasks = append(tasks, periodicTask{
					Tag: "cert monitor",
					Periodic: &task.Periodic{
						Interval: time.Duration(l.Lego.UpdatePeriodic) * time.Second * 60,
						Execute:  ln.CertMonitor,
					},
				})
			}
		case "dot":
			l.Address = rdns.AddressWithDefault(l.Address, rdns.DoTPort)
			tlsConfig, err := GetTLSServerConfig(&l)
			if err != nil {
				return nil, err
			}
			ln := rdns.NewDoTListener(id, l.Address, rdns.DoTListenerOptions{TLSConfig: tlsConfig, ListenOptions: opt}, resolver)
			ln.Lego = &l.Lego
			ln.MutualTLS = l.MutualTLS
			listeners = append(listeners, ln)
			if l.Lego.CertMode != "" && l.Lego.CertMode != "none" {
				tasks = append(tasks, periodicTask{
					Tag: "cert monitor",
					Periodic: &task.Periodic{
						Interval: time.Duration(l.Lego.UpdatePeriodic) * time.Second * 60,
						Execute:  ln.CertMonitor,
					},
				})
			}
		case "dtls":
			l.Address = rdns.AddressWithDefault(l.Address, rdns.DTLSPort)
			dtlsConfig, err := GetDTLSServerConfig(&l)
			if err != nil {
				return nil, err
			}
			ln := rdns.NewDTLSListener(id, l.Address, rdns.DTLSListenerOptions{DTLSConfig: dtlsConfig, ListenOptions: opt, MutualTLS: l.MutualTLS}, resolver)
			ln.Lego = &l.Lego
			listeners = append(listeners, ln)
			if l.Lego.CertMode != "" && l.Lego.CertMode != "none" {
				tasks = append(tasks, periodicTask{
					Tag: "cert monitor",
					Periodic: &task.Periodic{
						Interval: time.Duration(l.Lego.UpdatePeriodic) * time.Second * 60,
						Execute:  ln.CertMonitor,
					},
				})
			}
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
			ln.Lego = &l.Lego
			ln.MutualTLS = l.MutualTLS
			listeners = append(listeners, ln)
			if l.Lego.CertMode != "" && l.Lego.CertMode != "none" {
				tasks = append(tasks, periodicTask{
					Tag: "cert monitor",
					Periodic: &task.Periodic{
						Interval: time.Duration(l.Lego.UpdatePeriodic) * time.Second * 60,
						Execute:  ln.CertMonitor,
					},
				})
			}
		case "doq":
			l.Address = rdns.AddressWithDefault(l.Address, rdns.DoQPort)

			tlsConfig, err := GetTLSServerConfig(&l)
			if err != nil {
				return nil, err
			}
			ln := rdns.NewQUICListener(id, l.Address, rdns.DoQListenerOptions{TLSConfig: tlsConfig, ListenOptions: opt}, resolver)
			ln.Lego = &l.Lego
			ln.MutualTLS = l.MutualTLS
			listeners = append(listeners, ln)
			if l.Lego.CertMode != "" && l.Lego.CertMode != "none" {
				tasks = append(tasks, periodicTask{
					Tag: "cert monitor",
					Periodic: &task.Periodic{
						Interval: time.Duration(l.Lego.UpdatePeriodic) * time.Second * 60,
						Execute:  ln.CertMonitor,
					},
				})
			}
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
		Tasks:     tasks,
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
