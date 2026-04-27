package libovsdb

import (
	"fmt"
	"sync"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
)

// ConnectionPool manages a pool of OVN database client connections
// to enable concurrent batch operations without overwhelming a single connection.
// The pool owns a stopCh that is passed to all clients during creation, ensuring
// SSL key-pair watcher goroutines are properly cleaned up when the pool is closed.
type ConnectionPool struct {
	clients []libovsdbclient.Client
	current int
	mu      sync.Mutex
	stopCh  chan struct{} // Pool-owned stop channel for client cleanup
	closed  bool          // Tracks whether pool has been closed
}

// NewConnectionPool creates a pool of OVN NB database connections.
// The createClient function receives a stopCh that will be closed when the pool is closed,
// ensuring proper cleanup of SSL watcher goroutines started by newClient().
func NewConnectionPool(size int, createClient func(stopCh <-chan struct{}) (libovsdbclient.Client, error)) (*ConnectionPool, error) {
	if size <= 0 {
		return nil, fmt.Errorf("connection pool size must be positive, got %d", size)
	}

	pool := &ConnectionPool{
		clients: make([]libovsdbclient.Client, size),
		stopCh:  make(chan struct{}),
	}

	// Create all clients with the pool's stopCh
	for i := 0; i < size; i++ {
		client, err := createClient(pool.stopCh)
		if err != nil {
			// Clean up already created clients AND stop their watchers
			pool.cleanup()
			return nil, fmt.Errorf("failed to create client %d: %v", i, err)
		}
		pool.clients[i] = client
	}

	return pool, nil
}

// cleanup closes all clients and stops their SSL watcher goroutines
func (p *ConnectionPool) cleanup() {
	// Close stopCh first to signal all SSL watchers to stop
	select {
	case <-p.stopCh:
		// Already closed
	default:
		close(p.stopCh)
	}

	// Then close all client connections
	for _, client := range p.clients {
		if client != nil {
			client.Close()
		}
	}
}

// GetClient returns the next client in round-robin fashion.
// Returns an error if the pool has been closed to prevent using closed connections.
func (p *ConnectionPool) GetClient() (libovsdbclient.Client, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return nil, fmt.Errorf("connection pool is closed")
	}

	client := p.clients[p.current]
	p.current = (p.current + 1) % len(p.clients)

	return client, nil
}

// Close closes all connections in the pool and stops SSL watcher goroutines.
// This must be called to avoid goroutine leaks from SSL key-pair watchers.
// Close is idempotent and safe to call multiple times.
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed {
		return // Already closed, nothing to do
	}

	p.closed = true
	p.cleanup()
}
