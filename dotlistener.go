package rdns

import (
	"crypto/tls"
	"fmt"
	"log"

	"github.com/XrayR-project/XrayR/common/mylego"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DoTListener is a DNS listener/server for DNS-over-TLS.
type DoTListener struct {
	*dns.Server
	id   string
	Lego *mylego.CertConfig
	MutualTLS bool
}

var _ Listener = &DoTListener{}

// DoTListenerOptions contains options used by the DNS-over-TLS server.
type DoTListenerOptions struct {
	ListenOptions

	TLSConfig *tls.Config
}

// Check Cert
func (s *DoTListener) CertMonitor() error {
	switch s.Lego.CertMode {
	case "dns", "http", "tls":
		lego, err := mylego.New(s.Lego)
		if err != nil {
			log.Print(err)
		}
		// Xray-core supports the OcspStapling certification hot renew
		_, _, _, _, err = lego.RenewCert()
		if err != nil {
			log.Print(err)
		}
		cert, key, ca, err := GetCertFile(s.Lego)
		if err != nil {
			fmt.Print(err)
		}

		tlsConfig, err := TLSServerConfig(ca, cert, key, s.MutualTLS)
		if err != nil {
			return err
		}

		s.Server.TLSConfig = tlsConfig
		err = s.Stop()
		if err != nil {
			fmt.Printf("failed to stop DTLS listener %s, err: %s", s.id, err)
		}
		err = s.Start()
		if err != nil {
			fmt.Printf("failed to start DTLS listener %s, err: %s", s.id, err)
		}
	}
	return nil
}

// NewDoTListener returns an instance of a DNS-over-TLS listener.
func NewDoTListener(id, addr string, opt DoTListenerOptions, resolver Resolver) *DoTListener {
	return &DoTListener{
		id: id,
		Server: &dns.Server{
			Addr:      addr,
			Net:       "tcp-tls",
			TLSConfig: opt.TLSConfig,
			Handler:   listenHandler(id, "dot", addr, resolver, opt.AllowedNet),
		},
	}
}

// Start the Dot server.
func (s DoTListener) Start() error {
	Log.WithFields(logrus.Fields{"id": s.id, "protocol": "dot", "addr": s.Addr}).Info("starting listener")
	return s.ListenAndServe()
}

// Stop the server.
func (s DoTListener) Stop() error {
	Log.WithFields(logrus.Fields{"id": s.id, "protocol": "dot", "addr": s.Addr}).Info("stopping listener")
	return s.Shutdown()
}

func (s DoTListener) String() string {
	return s.id
}
