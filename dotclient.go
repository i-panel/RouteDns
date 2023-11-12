package rdns

import (
	"crypto/tls"
	"log"
	"net"
	"time"

	"github.com/XrayR-project/XrayR/common/mylego"
	"github.com/miekg/dns"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

// DoTClient is a DNS-over-TLS resolver.
type DoTClient struct {
	id       string
	endpoint string
	pipeline *Pipeline
	// Pipeline also provides operation metrics.
	opt DoTClientOptions
}

// DoTClientOptions contains options used by the DNS-over-TLS resolver.
type DoTClientOptions struct {
	// Bootstrap address - IP to use for the serivce instead of looking up
	// the service's hostname with potentially plain DNS.
	BootstrapAddr string

	// Local IP to use for outbound connections. If nil, a local address is chosen.
	LocalAddr net.IP

	TLSConfig *tls.Config

	QueryTimeout time.Duration

	// Optional dialer, e.g. proxy
	Dialer Dialer
	Lego   *mylego.CertConfig
	PanelSocksDialer *Socks5Dialer
}

var _ Resolver = &DoTClient{}

// Check Cert
func (s *DoTClient) CertMonitor() error {
	switch s.opt.Lego.CertMode {
	case "dns", "http", "tls":
		lego, err := mylego.New(s.opt.Lego)
		if err != nil {
			log.Print(err)
		}
		// Xray-core supports the OcspStapling certification hot renew
		CertPath, KeyPath, CaPath, _, err := lego.RenewCert()
		if err != nil {
			log.Print(err)
		}
		tlsConfig, err := TLSClientConfig(CaPath, CertPath, KeyPath, s.opt.Lego.CertDomain)
		if err != nil {
			log.Print(err)
		}
		s.opt.TLSConfig = tlsConfig
		nResolver, err := NewDoTClient(s.id, s.endpoint, s.opt)
		if err != nil {
			log.Print(err)
		}
		s = nResolver
	}
	return nil
}

// NewDoTClient instantiates a new DNS-over-TLS resolver.
func NewDoTClient(id, endpoint string, opt DoTClientOptions) (*DoTClient, error) {
	if err := validEndpoint(endpoint); err != nil {
		return nil, err
	}

	client := GenericDNSClient{
		Net:       "tcp-tls",
		TLSConfig: opt.TLSConfig,
		Dialer:    opt.Dialer,
		PanelSocksDialer: opt.PanelSocksDialer,
		LocalAddr: opt.LocalAddr,
	}
	// If a bootstrap address was provided, we need to use the IP for the connection but the
	// hostname in the TLS handshake. The DNS library doesn't support custom dialers, so
	// instead set the ServerName in the TLS config to the name in the endpoint config, and
	// replace the name in the endpoint with the bootstrap IP.
	if opt.BootstrapAddr != "" {
		host, port, err := net.SplitHostPort(endpoint)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to parse dot endpoint '%s'", endpoint)
		}
		client.TLSConfig.ServerName = host
		endpoint = net.JoinHostPort(opt.BootstrapAddr, port)
	}
	return &DoTClient{
		opt:      opt,
		id:       id,
		endpoint: endpoint,
		pipeline: NewPipeline(id, endpoint, client, opt.QueryTimeout),
	}, nil
}

// Resolve a DNS query.
func (d *DoTClient) Resolve(q *dns.Msg, ci ClientInfo, PanelSocksDialer *Socks5Dialer) (*dns.Msg, error) {
	// Packing a message is not always a read-only operation, make a copy
	q = q.Copy()

	logger(d.id, q, ci).WithFields(logrus.Fields{
		"resolver": d.endpoint,
		"protocol": "dot",
	}).Debug("querying upstream resolver")

	// Add padding to the query before sending over TLS
	padQuery(q)
	if d.opt.PanelSocksDialer != nil {
		opt := d.opt
		opt.Dialer = PanelSocksDialer
		r, _ := NewDoTClient(d.id, d.endpoint, opt)
		return r.pipeline.Resolve(q)
	}
	return d.pipeline.Resolve(q)
}

func (d *DoTClient) String() string {
	return d.id
}
