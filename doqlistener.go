package rdns

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"expvar"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/XrayR-project/XrayR/common/mylego"
	"github.com/miekg/dns"
	quic "github.com/quic-go/quic-go"
	"github.com/sirupsen/logrus"
)

// DoQListener is a DNS listener/server for QUIC.
type DoQListener struct {
	id      string
	addr    string
	r       Resolver
	opt     DoQListenerOptions
	ln      *quic.Listener
	log     *logrus.Entry
	metrics *DoQListenerMetrics
	Lego *mylego.CertConfig
	MutualTLS bool
}

var _ Listener = &DoQListener{}

// DoQListenerOptions contains options used by the QUIC server.
type DoQListenerOptions struct {
	ListenOptions

	TLSConfig *tls.Config
}

type DoQListenerMetrics struct {
	ListenerMetrics

	// Count of connections initiated.
	connection *expvar.Int
	// Count of streams seen in all connections.
	stream *expvar.Int
}

func NewDoQListenerMetrics(id string) *DoQListenerMetrics {
	return &DoQListenerMetrics{
		ListenerMetrics: ListenerMetrics{
			query:    getVarInt("listener", id, "query"),
			response: getVarMap("listener", id, "response"),
			drop:     getVarInt("listener", id, "drop"),
			err:      getVarMap("listener", id, "error"),
		},
		connection: getVarInt("listener", id, "session"),
		stream:     getVarInt("listener", id, "stream"),
	}
}

func (s *DoQListener) CertMonitor() error {
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
		s.opt.TLSConfig = tlsConfig
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

// NewQuicListener returns an instance of a QUIC listener.
func NewQUICListener(id, addr string, opt DoQListenerOptions, resolver Resolver) *DoQListener {
	if opt.TLSConfig == nil {
		opt.TLSConfig = new(tls.Config)
	}
	opt.TLSConfig.NextProtos = []string{"doq"}
	l := &DoQListener{
		id:      id,
		addr:    addr,
		r:       resolver,
		opt:     opt,
		log:     Log.WithFields(logrus.Fields{"id": id, "protocol": "doq", "addr": addr}),
		metrics: NewDoQListenerMetrics(id),
	}
	return l
}

// Start the QUIC server.
func (s DoQListener) Start() error {
	var err error
	s.ln, err = quic.ListenAddr(s.addr, s.opt.TLSConfig, &quic.Config{})
	if err != nil {
		return err
	}
	s.log.Info("starting listener")

	for {
		connection, err := s.ln.Accept(context.Background())
		if err != nil {
			s.log.WithError(err).Warn("failed to accept")
			continue
		}
		s.log.Trace("started connection")

		go func() {
			s.handleConnection(connection)
			_ = connection.CloseWithError(DOQNoError, "")
			s.log.Trace("closing connection")
		}()
	}
}

// Stop the server.
func (s DoQListener) Stop() error {
	Log.WithFields(logrus.Fields{"protocol": "quic", "addr": s.addr}).Info("stopping listener")
	return s.ln.Close()
}
func getQuicOriginalIP(w quic.Connection) net.IP {
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
func (s DoQListener) handleConnection(connection quic.Connection) {
	tlsServerName := connection.ConnectionState().TLS.ServerName

	ci := ClientInfo{
		Listener:      s.id,
		TLSServerName: tlsServerName,
	}
	// switch addr := connection.RemoteAddr().(type) {
	// case *net.TCPAddr:
	// 	ci.SourceIP = addr.IP
	// case *net.UDPAddr:
	// 	ci.SourceIP = addr.IP
	// }

	// Get original client IP, considering CDN headers
	ci.SourceIP = getQuicOriginalIP(connection)

	log := s.log.WithField("client", connection.RemoteAddr())

	if !isAllowed(s.opt.AllowedNet, ci.SourceIP) {
		log.Debug("rejecting incoming connection")
		s.metrics.drop.Add(1)
		return
	}
	log.Trace("accepting incoming connection")
	s.metrics.connection.Add(1)

	for {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second) // TODO: configurable
		stream, err := connection.AcceptStream(ctx)
		if err != nil {
			cancel()
			break
		}
		log.WithField("stream", stream.StreamID()).Trace("opening stream")
		go func() {
			s.handleStream(stream, log, ci)
			cancel()
			log.WithField("stream", stream.StreamID()).Trace("closing stream")
		}()
	}
}

func (s DoQListener) handleStream(stream quic.Stream, log *logrus.Entry, ci ClientInfo) {
	// DNS over QUIC uses one stream per query/response.
	defer stream.Close()
	s.metrics.stream.Add(1)

	// DoQ requires a length prefix, like TCP
	var length uint16
	if err := binary.Read(stream, binary.BigEndian, &length); err != nil {
		s.metrics.err.Add("read", 1)
		log.WithError(err).Error("failed to read query")
		return
	}

	// Read the raw query
	b := make([]byte, length)
	_ = stream.SetReadDeadline(time.Now().Add(time.Second)) // TODO: configurable timeout
	if _, err := io.ReadFull(stream, b); err != nil {
		s.metrics.err.Add("read", 1)
		log.WithError(err).Error("failed to read query")
		return
	}

	// Decode the query
	q := new(dns.Msg)
	if err := q.Unpack(b); err != nil {
		s.metrics.err.Add("unpack", 1)
		log.WithError(err).Error("failed to decode query")
		return
	}
	log = log.WithField("qname", qName(q))
	log.Debug("received query")
	s.metrics.query.Add(1)

	// Receiving a edns-tcp-keepalive EDNS(0) option is a fatal error according to the RFC
	edns0 := q.IsEdns0()
	if edns0 != nil {
		for _, opt := range edns0.Option {
			if opt.Option() == dns.EDNS0TCPKEEPALIVE {
				log.Error("received edns-tcp-keepalive, aborting")
				s.metrics.err.Add("keepalive", 1)
				return
			}
		}
	}

	// Resolve the query using the next hop
	a, err := s.r.Resolve(q, ci, nil)
	if err != nil {
		log.WithError(err).Error("failed to resolve")
		a = new(dns.Msg)
		a.SetRcode(q, dns.RcodeServerFailure)
	}

	p, err := a.Pack()
	if err != nil {
		log.WithError(err).Error("failed to encode response")
		s.metrics.err.Add("encode", 1)
		return
	}

	// Add a length prefix
	out := make([]byte, 2+len(p))
	binary.BigEndian.PutUint16(out, uint16(len(p)))
	copy(out[2:], p)

	// Send the response
	_ = stream.SetWriteDeadline(time.Now().Add(time.Second)) // TODO: configurable timeout
	if _, err = stream.Write(out); err != nil {
		s.metrics.err.Add("send", 1)
		log.WithError(err).Error("failed to send response")
	}
	s.metrics.response.Add(rCode(a), 1)
}

func (s DoQListener) String() string {
	return s.id
}
