package rdns

import (
	"github.com/miekg/dns"
)

// Fastest is a resolver group that queries all resolvers concurrently for
// the same query, then returns the user selected servers response only.
type PanelRotate struct {
	id        string
	resolvers Resolver
	PanelResolvers []Resolver
}

var _ Resolver = &PanelRotate{}

// NewFastest returns a new instance of a resolver group that returns the fastest
// response from all its resolvers.
func NewPanelRotate(id string, resolvers Resolver, panelResolvers ...Resolver) *PanelRotate {
	return &PanelRotate{
		id:        id,
		resolvers: resolvers,
		PanelResolvers: panelResolvers,
	}
}

// Resolve a DNS query by sending it to all resolvers and returning the fastest
// non-error response
func (r *PanelRotate) Resolve(q *dns.Msg, ci ClientInfo) (*dns.Msg, error) {
	log := logger(r.id, q, ci)

	type response struct {
		r   Resolver
		a   *dns.Msg
		err error
	}

	responseCh := make(chan response, len(r.PanelResolvers))

	// Send the query to all resolvers. The responses are collected in a buffered channel
	for _, resolver := range r.PanelResolvers {
		resolver := resolver
		go func() {
			a, err := resolver.Resolve(q, ci)
			responseCh <- response{resolver, a, err}
		}()
	}

	// Wait for responses, the first one that is successful is returned while the remaining open requests
	// are abandoned.
	var i int
	for resolverResponse := range responseCh {
		resolver, a, err := resolverResponse.r, resolverResponse.a, resolverResponse.err
		if err == nil && (a == nil || a.Rcode != dns.RcodeServerFailure) { // Return immediately if successful
			log.WithField("resolver", resolver.String()).Trace("using response from resolver")
			return a, err
		}
		log.WithField("resolver", resolver.String()).WithError(err).Debug("resolver returned failure, waiting for next response")

		// If all responses were bad, return the last one
		if i++; i >= len(r.PanelResolvers) {
			return a, err
		}
	}
	return nil, nil // should never be reached
}

func (r *PanelRotate) String() string {
	return r.id
}
