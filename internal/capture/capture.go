package capture

import (
	"context"
	"crypto/tls"
	"net"
	"sync"

	"github.com/jsandas/tls-client-scanner/internal/clienthello"
)

type contextKey struct{}

// Observation holds the ClientHello associated with one accepted connection.
type Observation struct {
	mu       sync.RWMutex
	hello    clienthello.Hello
	observed bool
}

// Get returns the observed ClientHello and whether one was captured.
func (o *Observation) Get() (clienthello.Hello, bool) {
	o.mu.RLock()
	defer o.mu.RUnlock()

	return o.hello, o.observed
}

func (o *Observation) store(info *tls.ClientHelloInfo) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.hello = clienthello.FromTLS(info)
	o.observed = true
}

// Listener decorates accepted connections with a per-connection observation.
type Listener struct {
	net.Listener
}

// Accept returns a connection carrying an empty ClientHello observation.
func (l Listener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	return &connection{
		Conn:        conn,
		observation: &Observation{},
	}, nil
}

// Observe records the ClientHello on its originating connection.
func Observe(info *tls.ClientHelloInfo) {
	if observation := fromConnection(info.Conn); observation != nil {
		observation.store(info)
	}
}

// ConnContext attaches the connection's observation to the request context.
func ConnContext(ctx context.Context, conn net.Conn) context.Context {
	return context.WithValue(ctx, contextKey{}, fromConnection(conn))
}

// FromContext gets the ClientHello observation for the current connection.
func FromContext(ctx context.Context) (*Observation, bool) {
	observation, ok := ctx.Value(contextKey{}).(*Observation)

	return observation, ok
}

type connection struct {
	net.Conn
	observation *Observation
}

type netConnection interface {
	NetConn() net.Conn
}

func fromConnection(conn net.Conn) *Observation {
	const maxDepth = 4

	for range maxDepth {
		if captured, ok := conn.(*connection); ok {
			return captured.observation
		}

		wrapped, ok := conn.(netConnection)
		if !ok {
			return nil
		}

		conn = wrapped.NetConn()
	}

	return nil
}
