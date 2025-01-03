package rdns

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/XrayR-project/XrayR/common/mylego"
	"github.com/miekg/dns"
	"github.com/sirupsen/logrus"
)

// DNSListener is a standard DNS listener for UDP or TCP.
type DNSListener struct {
	*dns.Server
	id string
	Lego *mylego.CertConfig
	MutualTLS bool
}

var _ Listener = &DNSListener{}

type ListenOptions struct {
	// Network allowed to query this listener.
	AllowedNet []*net.IPNet
}

func (s *DNSListener) CertMonitor() error {
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
		s.TLSConfig = tlsConfig
		err = s.Stop()
		if err != nil {
			fmt.Printf("failed to stop DTLS listener %s, err: %s", s.id,err)
		}
		err = s.Start()
		if err != nil {
			fmt.Printf("failed to start DTLS listener %s, err: %s", s.id,err)
		}
	}
	return nil
}

// NewDNSListener returns an instance of either a UDP or TCP DNS listener.
func NewDNSListener(id, addr, net string, opt ListenOptions, resolver Resolver) *DNSListener {
	return &DNSListener{
		id: id,
		Server: &dns.Server{
			Addr:    addr,
			Net:     net,
			Handler: listenHandler(id, net, addr, resolver, opt.AllowedNet),
		},
	}
}

// Start the DNS listener.
func (s DNSListener) Start() error {
	Log.WithFields(logrus.Fields{
		"id":       s.id,
		"protocol": s.Net,
		"addr":     s.Addr}).Info("starting listener")
	return s.ListenAndServe()
}

func (s DNSListener) Stop() error {
	return s.Shutdown()
}

func (s DNSListener) String() string {
	return s.id
}

func getOriginalIP(w dns.ResponseWriter) net.IP {
	// Try to get original IP from common CDN headers if available
	if r, ok := w.(interface{ Request() *http.Request }); ok {
		req := r.Request()
		if req != nil {
			// Check common CDN headers in order of preference
			headers := []string{
				"x-real-ip",        // nginx
				"CF-Connecting-IP", // Cloudflare
				"X-Forwarded-For",  // General use
				"True-Client-IP",   // Akamai
				"X-Original-Forwarded-For",
			}

			for _, header := range headers {
				if ip := req.Header.Get(header); ip != "" {
					// Parse the IP address
					if parsedIP := net.ParseIP(strings.TrimSpace(strings.Split(ip, ",")[0])); parsedIP != nil {
						return parsedIP
					}
				}
			}
		}
	}

	// Fallback to direct connection IP if no CDN headers found
	switch addr := w.RemoteAddr().(type) {
	case *net.TCPAddr:
		return addr.IP
	case *net.UDPAddr:
		return addr.IP
	default:
		return nil
	}
}

// DNS handler to forward all incoming requests to a given resolver.
func listenHandler(id, protocol, addr string, r Resolver, allowedNet []*net.IPNet) dns.HandlerFunc {
	metrics := NewListenerMetrics("listener", id)
	return func(w dns.ResponseWriter, req *dns.Msg) {
		var err error

		ci := ClientInfo{
			Listener: id,
		}

		if r, ok := w.(interface{ ConnectionState() *tls.ConnectionState }); ok {
			connState := r.ConnectionState()
			if connState != nil {
				ci.TLSServerName = connState.ServerName
			}
		}

		// switch addr := w.RemoteAddr().(type) {
		// case *net.TCPAddr:
		// 	ci.SourceIP = addr.IP
		// case *net.UDPAddr:
		// 	ci.SourceIP = addr.IP
		// }

		// Get original client IP, considering CDN headers
		ci.SourceIP = getOriginalIP(w)

		log := Log.WithFields(logrus.Fields{"id": id, "client": ci.SourceIP, "qname": qName(req), "protocol": protocol, "addr": addr})
		log.Debug("received query")
		metrics.query.Add(1)

		a := new(dns.Msg)
		if isAllowed(allowedNet, ci.SourceIP) {
			log.WithField("resolver", r.String()).Trace("forwarding query to resolver")
			a, err = r.Resolve(req, ci, nil)
			if err != nil {
				metrics.err.Add("resolve", 1)
				log.WithError(err).Error("failed to resolve")
				a = servfail(req)
			}
		} else {
			metrics.err.Add("acl", 1)
			log.Debug("refusing client ip")
			a.SetRcode(req, dns.RcodeRefused)
		}

		// A nil response from the resolvers means "drop", close the connection
		if a == nil {
			w.Close()
			metrics.drop.Add(1)
			return
		}

		// If the client asked via DoT and EDNS0 is enabled, the response should be padded for extra security.
		// See rfc7830 and rfc8467.
		if protocol == "dot" || protocol == "dtls" {
			padAnswer(req, a)
		} else {
			stripPadding(a)
		}

		// Check the response actually fits if the query was sent over UDP. If not, respond with TC flag.
		if protocol == "udp" || protocol == "dtls" {
			maxSize := dns.MinMsgSize
			if edns0 := req.IsEdns0(); edns0 != nil {
				maxSize = int(edns0.UDPSize())
			}
			a.Truncate(maxSize)
		}

		metrics.response.Add(rCode(a), 1)
		_ = w.WriteMsg(a)
	}
}

func isAllowed(allowedNet []*net.IPNet, ip net.IP) bool {
	if len(allowedNet) == 0 {
		return true
	}
	for _, net := range allowedNet {
		if net.Contains(ip) {
			return true
		}
	}
	return false
}
