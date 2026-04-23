# Connection Pool Goroutine Leak Fix

## Issue

The original `ConnectionPool` implementation had a critical resource leak:

### The Problem

1. `libovsdb/libovsdb.go:newClient()` starts an SSL key-pair watcher goroutine
2. This goroutine runs until the `stopCh` passed to `newClient()` is closed
3. The comment explicitly states: "the stopCh is required to ensure the goroutine for ssl cert update is not leaked"
4. `client.Close()` does NOT close the stopCh - it only closes the connection
5. In `ConnectionPool`, if client creation failed partway through:
   - We called `client.Close()` on already-created clients
   - But their SSL watcher goroutines kept running
   - They would only stop when the outer controller stopCh closed
   - **This leaked goroutines for the lifetime of the controller**

### Example Leak Scenario

```go
// Original buggy code:
pool, err := NewConnectionPool(4, func() (client.Client, error) {
    return NewNBClient(controllerStopCh)  // Uses controller's stopCh
})

// If 3rd client creation fails:
// - Client 0: Close() called ✓, but SSL watcher still running ✗
// - Client 1: Close() called ✓, but SSL watcher still running ✗
// - Client 2: Creation failed
// - Result: 2 leaked goroutines until controller stops!
```

## The Fix

**Make the ConnectionPool own its own stopCh** that is:
1. Created when the pool is created
2. Passed to all clients during creation
3. Closed when the pool is closed

### Implementation

```go
type ConnectionPool struct {
    clients []libovsdbclient.Client
    current int
    mu      sync.Mutex
    stopCh  chan struct{} // ← Pool-owned stop channel
}

func NewConnectionPool(size int, createClient func(stopCh <-chan struct{}) (libovsdbclient.Client, error)) (*ConnectionPool, error) {
    pool := &ConnectionPool{
        clients: make([]libovsdbclient.Client, size),
        stopCh:  make(chan struct{}), // ← Create pool's own stopCh
    }

    for i := 0; i < size; i++ {
        client, err := createClient(pool.stopCh) // ← Pass pool's stopCh
        if err != nil {
            pool.cleanup() // ← Proper cleanup on failure
            return nil, fmt.Errorf("failed to create client %d: %v", i, err)
        }
        pool.clients[i] = client
    }

    return pool, nil
}

func (p *ConnectionPool) cleanup() {
    // CRITICAL ORDER: Close stopCh FIRST to stop SSL watchers
    select {
    case <-p.stopCh:
        // Already closed
    default:
        close(p.stopCh) // ← Stop all SSL watcher goroutines
    }

    // THEN close client connections
    for _, client := range p.clients {
        if client != nil {
            client.Close() // ← Close connections
        }
    }
}

func (p *ConnectionPool) Close() {
    p.mu.Lock()
    defer p.mu.Unlock()
    p.cleanup() // ← Proper cleanup including SSL watchers
}
```

## Why This Works

### Proper Cleanup Order

1. **Close stopCh first** → Signals all SSL watcher goroutines to exit
2. **Close clients second** → Closes network connections
3. **No goroutine leaks** → All resources properly released

### Error Handling

If client creation fails partway through:
- `cleanup()` is called
- `stopCh` is closed → Stops SSL watchers for already-created clients
- Clients are closed → Closes connections
- **No leaks**

### Signature Change

The `createClient` function signature changed to receive stopCh:

**Before:**
```go
func(stopCh <-chan struct{}) (libovsdbclient.Client, error)
```

**After:**
```go
func(stopCh <-chan struct{}) (libovsdbclient.Client, error)
```

This allows the caller to pass the appropriate stopCh (controller's or pool's).

## Impact

### Before (Leaked Goroutines)
- Pool with 4 clients created
- 3rd client fails
- 2 SSL watcher goroutines leak until controller shutdown
- In a long-running controller, this adds up
- Memory leak grows over time with repeated pool creation attempts

### After (No Leaks)
- Pool with 4 clients created
- 3rd client fails
- `cleanup()` closes pool's stopCh
- All SSL watchers for clients 0 and 1 stop immediately
- Clients 0 and 1 connections closed
- **Zero leaked goroutines**

## Testing

To verify the fix:

```go
// Test that stopCh is closed on pool.Close()
pool, _ := NewConnectionPool(2, func(stopCh <-chan struct{}) (client.Client, error) {
    // Create client
    client := createTestClient(stopCh)
    
    // Verify stopCh is not closed yet
    select {
    case <-stopCh:
        t.Fatal("stopCh should not be closed during creation")
    default:
    }
    
    return client, nil
})

// Close the pool
pool.Close()

// Verify stopCh is now closed (would be passed to clients)
// This would stop all SSL watcher goroutines
```

## Related Code

See `go-controller/pkg/libovsdb/libovsdb.go`:

```go
// Line 73-74:
// the stopCh is required to ensure the goroutine for ssl cert
// update is not leaked

func newClient(cfg config.OvnAuthConfig, dbModel model.ClientDBModel, stopCh <-chan struct{}, opts ...client.Option) (client.Client, error) {
    // ...
    if cfg.Scheme == config.OvnDBSchemeSSL {
        // ...
        updateFn, err = newSSLKeyPairWatcherFunc(cfg.Cert, cfg.PrivKey, tlsConfig)
        // ...
    }
    
    // Line 122: Starts SSL watcher goroutine
    if updateFn != nil {
        go updateFn(client, stopCh) // ← This goroutine needs stopCh closed
    }
    // ...
}
```

## Additional Fix: Shutdown Race Condition

### Problem
After `Close()` runs, `GetClient()` could still return clients from the closed pool:
- Batch worker racing with shutdown gets a closed connection
- OVN transaction fails with confusing "connection closed" error
- No clear indication that the pool itself is closed

### Fix
1. **Track closed state:**
   ```go
   type ConnectionPool struct {
       closed bool  // Tracks whether pool has been closed
   }
   ```

2. **GetClient returns error when closed:**
   ```go
   func (p *ConnectionPool) GetClient() (libovsdbclient.Client, error) {
       p.mu.Lock()
       defer p.mu.Unlock()
       
       if p.closed {
           return nil, fmt.Errorf("connection pool is closed")
       }
       
       // ... return client
   }
   ```

3. **Make Close idempotent:**
   ```go
   func (p *ConnectionPool) Close() {
       p.mu.Lock()
       defer p.mu.Unlock()
       
       if p.closed {
           return // Already closed
       }
       
       p.closed = true
       p.cleanup()
   }
   ```

### Impact

| Scenario | Before | After |
|----------|--------|-------|
| **GetClient after Close** | Returns closed client | ✅ Returns clear error |
| **Batch worker at shutdown** | Transaction fails mysteriously | ✅ Gets "pool closed" error |
| **Multiple Close calls** | Potential double-close panic | ✅ Idempotent, safe |
| **Error clarity** | "connection closed" | ✅ "connection pool is closed" |

## Summary

✅ **Fixed:** Pool owns its own stopCh  
✅ **Fixed:** stopCh passed to all clients during creation  
✅ **Fixed:** stopCh closed before clients on cleanup  
✅ **Fixed:** Proper cleanup on partial failure  
✅ **Fixed:** No goroutine leaks  
✅ **Fixed:** GetClient detects closed pool  
✅ **Fixed:** Close is idempotent  
✅ **Fixed:** Clear error messages during shutdown  

**Result:** Safe resource management with zero goroutine leaks and proper shutdown semantics.
