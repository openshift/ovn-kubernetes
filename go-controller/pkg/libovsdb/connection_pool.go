package libovsdb

import (
	"fmt"
	"sync"

	libovsdbclient "github.com/ovn-kubernetes/libovsdb/client"
)

// ConnectionPool manages a pool of OVN database client connections
// to enable concurrent batch operations without overwhelming a single connection.
type ConnectionPool struct {
	clients []libovsdbclient.Client
	current int
	mu      sync.Mutex
}

// NewConnectionPool creates a pool of OVN NB database connections
func NewConnectionPool(size int, createClient func() (libovsdbclient.Client, error)) (*ConnectionPool, error) {
	if size <= 0 {
		return nil, fmt.Errorf("connection pool size must be positive, got %d", size)
	}

	pool := &ConnectionPool{
		clients: make([]libovsdbclient.Client, size),
	}

	for i := 0; i < size; i++ {
		client, err := createClient()
		if err != nil {
			// Clean up already created clients
			for j := 0; j < i; j++ {
				pool.clients[j].Close()
			}
			return nil, fmt.Errorf("failed to create client %d: %v", i, err)
		}
		pool.clients[i] = client
	}

	return pool, nil
}

// GetClient returns the next client in round-robin fashion
func (p *ConnectionPool) GetClient() libovsdbclient.Client {
	p.mu.Lock()
	defer p.mu.Unlock()

	client := p.clients[p.current]
	p.current = (p.current + 1) % len(p.clients)

	return client
}

// Close closes all connections in the pool
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, client := range p.clients {
		client.Close()
	}
}
