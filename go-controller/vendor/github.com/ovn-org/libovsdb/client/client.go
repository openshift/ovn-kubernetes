package client

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"reflect"
	"strings"
	"sync"

	"github.com/cenkalti/backoff/v4"
	"github.com/cenkalti/rpc2"
	"github.com/cenkalti/rpc2/jsonrpc"
	"github.com/google/uuid"
	"github.com/ovn-org/libovsdb/cache"
	"github.com/ovn-org/libovsdb/mapper"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
	"github.com/ovn-org/libovsdb/ovsdb/serverdb"
)

// Constants defined for libovsdb
const (
	SSL  = "ssl"
	TCP  = "tcp"
	UNIX = "unix"
)

const serverDB = "_Server"

// ErrNotConnected is an error returned when the client is not connected
var ErrNotConnected = errors.New("not connected")

// Client represents an OVSDB Client Connection
// It provides all the necessary functionality to Connect to a server,
// perform transactions, and build your own replica of the database with
// Monitor or MonitorAll. It also provides a Cache that is populated from OVSDB
// update notifications.
type Client interface {
	Connect(context.Context) error
	Disconnect()
	Close()
	Schema() *ovsdb.DatabaseSchema
	Cache() *cache.TableCache
	SetOption(Option) error
	Connected() bool
	DisconnectNotify() chan struct{}
	Echo(context.Context) error
	Transact(context.Context, ...ovsdb.Operation) ([]ovsdb.OperationResult, error)
	Monitor(context.Context, ...TableMonitor) (MonitorCookie, error)
	MonitorAll(context.Context) (MonitorCookie, error)
	MonitorCancel(ctx context.Context, cookie MonitorCookie) error
	NewTableMonitor(m model.Model, fields ...interface{}) TableMonitor
	CurrentEndpoint() string
	API
}

// MonitorCookie is the struct we pass to correlate from updates back to their
// originating Monitor request.
type MonitorCookie struct {
	DatabaseName string `json:"databaseName"`
	ID           string `json:"id"`
}

// ovsdbClient is an OVSDB client
type ovsdbClient struct {
	options        *options
	rpcClient      *rpc2.Client
	rpcMutex       sync.RWMutex
	activeEndpoint string

	// The name of the "primary" database - that is to say, the DB
	// that the user expects to interact with.
	primaryDBName string
	databases     map[string]*database

	stopCh        chan struct{}
	disconnect    chan struct{}
	shutdown      bool
	shutdownMutex sync.Mutex
}

// database is everything needed to map between go types and an ovsdb Database
type database struct {
	model       *model.DBModel
	schema      *ovsdb.DatabaseSchema
	schemaMutex sync.RWMutex
	cache       *cache.TableCache
	cacheMutex  sync.RWMutex

	api API

	// any ongoing monitors, so we can re-create them if we disconnect
	monitors      map[string][]TableMonitor
	monitorsMutex sync.Mutex
}

// NewOVSDBClient creates a new OVSDB Client with the provided
// database model. The client can be configured using one or more Option(s),
// like WithTLSConfig. If no WithEndpoint option is supplied, the default of
// unix:/var/run/openvswitch/ovsdb.sock is used
func NewOVSDBClient(databaseModel *model.DBModel, opts ...Option) (Client, error) {
	return newOVSDBClient(databaseModel, opts...)
}

// newOVSDBClient creates a new ovsdbClient
func newOVSDBClient(databaseModel *model.DBModel, opts ...Option) (*ovsdbClient, error) {
	ovs := &ovsdbClient{
		primaryDBName: databaseModel.Name(),
		databases: map[string]*database{
			databaseModel.Name(): {
				model:    databaseModel,
				monitors: make(map[string][]TableMonitor),
			},
		},
		disconnect: make(chan struct{}),
	}
	var err error
	ovs.options, err = newOptions(opts...)
	if err != nil {
		return nil, err
	}

	// if we should only connect to the leader, then add the special "_Server" database as well
	if ovs.options.leaderOnly {
		sm, err := serverdb.FullDatabaseModel()
		if err != nil {
			return nil, fmt.Errorf("could not initialize model _Server: %w", err)
		}
		ovs.databases[serverDB] = &database{
			model:    sm,
			monitors: make(map[string][]TableMonitor),
		}
	}
	return ovs, nil
}

// Connect opens a connection to an OVSDB Server using the
// endpoint provided when the Client was created.
// The connection can be configured using one or more Option(s), like WithTLSConfig
// If no WithEndpoint option is supplied, the default of unix:/var/run/openvswitch/ovsdb.sock is used
func (o *ovsdbClient) Connect(ctx context.Context) error {
	if err := o.connect(ctx, false); err != nil {
		return err
	}

	if o.options.leaderOnly {
		if err := o.watchForLeaderChange(); err != nil {
			return err
		}
	}
	return nil
}

func (o *ovsdbClient) connect(ctx context.Context, reconnect bool) error {
	o.rpcMutex.Lock()
	defer o.rpcMutex.Unlock()
	if o.rpcClient != nil {
		return nil
	}

	connected := false
	connectErrors := []error{}
	for _, endpoint := range o.options.endpoints {
		u, err := url.Parse(endpoint)
		if err != nil {
			return err
		}
		if err := o.tryEndpoint(ctx, u); err != nil {
			connectErrors = append(connectErrors,
				fmt.Errorf("failed to connect to %s: %w", endpoint, err))
			continue
		} else {
			log.Printf("libovsdb: connected to %s", endpoint)
			o.activeEndpoint = endpoint
			connected = true
			break
		}
	}

	if !connected {
		if len(connectErrors) == 1 {
			return connectErrors[0]
		}
		combined := []string{}
		for _, e := range connectErrors {
			combined = append(combined, e.Error())
		}

		return fmt.Errorf("unable to connect to any endpoints: %s", strings.Join(combined, ". "))
	}

	// if we're reconnecting, re-start all the monitors
	if reconnect {
		log.Printf("libovsdb: reconnected - restarting monitors")
		for dbName, db := range o.databases {
			db.monitorsMutex.Lock()
			defer db.monitorsMutex.Unlock()
			for id, request := range db.monitors {
				err := o.monitor(ctx, MonitorCookie{DatabaseName: dbName, ID: id}, true, request...)
				if err != nil {
					return err
				}
			}
		}
	}

	go o.handleDisconnectNotification()
	for _, db := range o.databases {
		go db.cache.Run(o.stopCh)
	}

	return nil
}

func (o *ovsdbClient) tryEndpoint(ctx context.Context, u *url.URL) error {
	log.Printf("libovsdb: trying to connect to DB %s", u)
	var dialer net.Dialer
	var err error
	var c net.Conn

	switch u.Scheme {
	case UNIX:
		c, err = dialer.DialContext(ctx, u.Scheme, u.Path)
	case TCP:
		c, err = dialer.DialContext(ctx, u.Scheme, u.Opaque)
	case SSL:
		dialer := tls.Dialer{
			Config: o.options.tlsConfig,
		}
		c, err = dialer.DialContext(ctx, "tcp", u.Opaque)
	default:
		err = fmt.Errorf("unknown network protocol %s", u.Scheme)
	}

	if err != nil {
		return fmt.Errorf("failed to open connection: %w", err)
	}

	if err = o.createRPC2Client(c); err != nil {
		return fmt.Errorf("failed to open RPC connection: %w", err)
	}

	// from now on, if err is nil, always tear down the RPC session
	defer func() {
		if err != nil {
			o.rpcClient.Close()
			o.rpcClient = nil
		}
	}()

	serverDBNames, err := o.listDbs(ctx)
	if err != nil {
		return err
	}

	// for every requested database, ensure the DB exists in the server and
	// that the schema matches what we expect.
	for dbName, db := range o.databases {
		// check the server has what we want
		found := false
		for _, name := range serverDBNames {
			if name == dbName {
				found = true
				break
			}
		}
		if !found {
			err = fmt.Errorf("target database %s not found", dbName)
			return err
		}

		// load and validate the schema
		schema, err := o.getSchema(ctx, dbName)
		if err != nil {
			return err
		}

		errors := db.model.Validate(schema)
		if len(errors) > 0 {
			var combined []string
			for _, err := range errors {
				combined = append(combined, err.Error())
			}
			err = fmt.Errorf("database %s validation error (%d): %s", dbName, len(errors),
				strings.Join(combined, ". "))
			return err
		}

		db.schemaMutex.Lock()
		db.schema = schema
		db.schemaMutex.Unlock()

		db.cacheMutex.Lock()
		if db.cache == nil {
			db.cache, err = cache.NewTableCache(schema, db.model, nil)
			if err != nil {
				db.cacheMutex.Unlock()
				return err
			}
			db.api = newAPI(db.cache)
		} else {
			db.cache.Purge(db.schema)
		}
		db.cacheMutex.Unlock()
	}

	// check that this is the leader
	if o.options.leaderOnly {
		var leader bool
		leader, err = o.isEndpointLeader(ctx)
		if err != nil {
			return err
		}
		if !leader {
			err = fmt.Errorf("endpoint is not leader")
			return err
		}
	}
	return nil
}

// createRPC2Client creates an rpcClient using the provided connection
// It is also responsible for setting up go routines for client-side event handling
// Should only be called when the mutex is held
func (o *ovsdbClient) createRPC2Client(conn net.Conn) error {
	o.stopCh = make(chan struct{})
	o.rpcClient = rpc2.NewClientWithCodec(jsonrpc.NewJSONCodec(conn))
	o.rpcClient.SetBlocking(true)
	o.rpcClient.Handle("echo", func(_ *rpc2.Client, args []interface{}, reply *[]interface{}) error {
		return o.echo(args, reply)
	})
	o.rpcClient.Handle("update", func(_ *rpc2.Client, args []json.RawMessage, reply *[]interface{}) error {
		return o.update(args, reply)
	})
	go o.rpcClient.Run()
	return nil
}

// isEndpointLeader returns true if the currently connected endpoint is leader.
// assumes rpcMutex is held
func (o *ovsdbClient) isEndpointLeader(ctx context.Context) (bool, error) {
	op := ovsdb.Operation{
		Op:      ovsdb.OperationSelect,
		Table:   "Database",
		Columns: []string{"name", "model", "leader"},
	}
	results, err := o.transact(ctx, serverDB, op)
	if err != nil {
		return false, fmt.Errorf("could not check if server was leader: %w", err)
	}
	// for now, if no rows are returned, just accept this server
	if len(results) != 1 {
		return true, nil
	}
	result := results[0]
	if len(result.Rows) == 0 {
		return true, nil
	}

	for _, row := range result.Rows {
		dbName, ok := row["name"].(string)
		if !ok {
			return false, fmt.Errorf("could not parse name")
		}
		if dbName != o.primaryDBName {
			continue
		}

		model, ok := row["model"].(string)
		if !ok {
			return false, fmt.Errorf("could not parse model")
		}

		// the database reports whether or not it is part of a cluster via the
		// "model" column. If it's not clustered, it is by definition leader.
		if model != serverdb.DatabaseModelClustered {
			return true, nil
		}

		leader, ok := row["leader"].(bool)
		if !ok {
			return false, fmt.Errorf("could not parse leader")
		}
		return leader, nil
	}

	// Extremely unlikely: there is no _Server row for the desired DB (which we made sure existed)
	// for now, just continue
	log.Println("libovsdb: couldn't find a matching entry in _Server!")
	return true, nil
}

func (o *ovsdbClient) primaryDB() *database {
	return o.databases[o.primaryDBName]
}

// Schema returns the DatabaseSchema that is being used by the client
// it will be nil until a connection has been established
func (o *ovsdbClient) Schema() *ovsdb.DatabaseSchema {
	db := o.primaryDB()
	db.schemaMutex.RLock()
	defer db.schemaMutex.RUnlock()
	return db.schema
}

// Cache returns the TableCache that is populated from
// ovsdb update notifications. It will be nil until a connection
// has been established, and empty unless you call Monitor
func (o *ovsdbClient) Cache() *cache.TableCache {
	db := o.primaryDB()
	db.cacheMutex.RLock()
	defer db.cacheMutex.RUnlock()
	return db.cache
}

// SetOption sets a new value for an option.
// It may only be called when the client is not connected
func (o *ovsdbClient) SetOption(opt Option) error {
	o.rpcMutex.RLock()
	defer o.rpcMutex.RUnlock()
	if o.rpcClient != nil {
		return fmt.Errorf("cannot set option when client is connected")
	}
	return opt(o.options)
}

// Connected returns whether or not the client is currently connected to the server
func (o *ovsdbClient) Connected() bool {
	o.rpcMutex.RLock()
	defer o.rpcMutex.RUnlock()
	return o.rpcClient != nil
}

func (o *ovsdbClient) CurrentEndpoint() string {
	o.rpcMutex.RLock()
	defer o.rpcMutex.RUnlock()
	if o.rpcClient == nil {
		return ""
	}
	return o.activeEndpoint
}

// DisconnectNotify returns a channel which will notify the caller when the
// server has disconnected
func (o *ovsdbClient) DisconnectNotify() chan struct{} {
	return o.disconnect
}

// RFC 7047 : Section 4.1.6 : Echo
func (o *ovsdbClient) echo(args []interface{}, reply *[]interface{}) error {
	*reply = args
	return nil
}

// RFC 7047 : Update Notification Section 4.1.6
// params is an array of length 2: [json-value, table-updates]
// - json-value: the arbitrary json-value passed when creating the Monitor, i.e. the "cookie"
// - table-updates: map of table name to table-update. Table-update is a map of uuid to (old, new) row paris
func (o *ovsdbClient) update(params []json.RawMessage, reply *[]interface{}) error {
	cookie := MonitorCookie{}
	if len(params) > 2 {
		return fmt.Errorf("update requires exactly 2 args")
	}
	err := json.Unmarshal(params[0], &cookie)
	if err != nil {
		return err
	}
	var updates ovsdb.TableUpdates
	err = json.Unmarshal(params[1], &updates)
	if err != nil {
		return err
	}
	db := o.databases[cookie.DatabaseName]
	if db == nil {
		return fmt.Errorf("update: invalid database name: %s unknown", cookie.DatabaseName)
	}
	// Update the local DB cache with the tableUpdates
	db.cacheMutex.RLock()
	db.cache.Update(cookie.ID, updates)
	db.cacheMutex.RUnlock()
	*reply = []interface{}{}
	return nil
}

// getSchema returns the schema in use for the provided database name
// RFC 7047 : get_schema
// Should only be called when mutex is held
func (o *ovsdbClient) getSchema(ctx context.Context, dbName string) (*ovsdb.DatabaseSchema, error) {
	args := ovsdb.NewGetSchemaArgs(dbName)
	var reply ovsdb.DatabaseSchema
	err := o.rpcClient.CallWithContext(ctx, "get_schema", args, &reply)
	if err != nil {
		if err == rpc2.ErrShutdown {
			return nil, ErrNotConnected
		}
		return nil, err
	}
	return &reply, err
}

// listDbs returns the list of databases on the server
// RFC 7047 : list_dbs
// Should only be called when mutex is held
func (o *ovsdbClient) listDbs(ctx context.Context) ([]string, error) {
	var dbs []string
	err := o.rpcClient.CallWithContext(ctx, "list_dbs", nil, &dbs)
	if err != nil {
		if err == rpc2.ErrShutdown {
			return nil, ErrNotConnected
		}
		return nil, fmt.Errorf("listdbs failure - %v", err)
	}
	return dbs, err
}

// Transact performs the provided Operations on the database
// RFC 7047 : transact
func (o *ovsdbClient) Transact(ctx context.Context, operation ...ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	o.rpcMutex.Lock()
	defer o.rpcMutex.Unlock()
	return o.transact(ctx, o.primaryDBName, operation...)
}

func (o *ovsdbClient) transact(ctx context.Context, dbName string, operation ...ovsdb.Operation) ([]ovsdb.OperationResult, error) {
	var reply []ovsdb.OperationResult
	db := o.databases[dbName]
	db.schemaMutex.RLock()
	schema := o.databases[dbName].schema
	db.schemaMutex.RUnlock()
	if schema == nil {
		return nil, fmt.Errorf("cannot transact to database %s: schema unknown", dbName)
	}
	if ok := schema.ValidateOperations(operation...); !ok {
		return nil, fmt.Errorf("validation failed for the operation")
	}

	args := ovsdb.NewTransactArgs(o.primaryDBName, operation...)

	if o.rpcClient == nil {
		return nil, ErrNotConnected
	}
	err := o.rpcClient.CallWithContext(ctx, "transact", args, &reply)
	if err != nil {
		if err == rpc2.ErrShutdown {
			return nil, ErrNotConnected
		}
		return nil, err
	}
	return reply, nil
}

// MonitorAll is a convenience method to monitor every table/column
func (o *ovsdbClient) MonitorAll(ctx context.Context) (MonitorCookie, error) {
	var options []TableMonitor
	for name := range o.primaryDB().model.Types() {
		options = append(options, TableMonitor{Table: name})
	}
	return o.Monitor(ctx, options...)
}

// MonitorCancel will request cancel a previously issued monitor request
// RFC 7047 : monitor_cancel
func (o *ovsdbClient) MonitorCancel(ctx context.Context, cookie MonitorCookie) error {
	var reply ovsdb.OperationResult
	args := ovsdb.NewMonitorCancelArgs(cookie)
	o.rpcMutex.Lock()
	defer o.rpcMutex.Unlock()
	if o.rpcClient == nil {
		return ErrNotConnected
	}
	err := o.rpcClient.CallWithContext(ctx, "monitor_cancel", args, &reply)
	if err != nil {
		if err == rpc2.ErrShutdown {
			return ErrNotConnected
		}
		return err
	}
	if reply.Error != "" {
		return fmt.Errorf("error while executing transaction: %s", reply.Error)
	}
	o.primaryDB().monitorsMutex.Lock()
	defer o.primaryDB().monitorsMutex.Unlock()
	delete(o.primaryDB().monitors, cookie.ID)
	return nil
}

// TableMonitor is a table to be monitored
type TableMonitor struct {
	// Table is the table to be monitored
	Table string
	// Fields are the fields in the model to monitor
	// If none are supplied, all fields will be used
	Fields []interface{}
	// Error will contain any errors caught in the creation of a TableMonitor
	Error error
}

func (o *ovsdbClient) NewTableMonitor(m model.Model, fields ...interface{}) TableMonitor {
	tableName := o.primaryDB().model.FindTable(reflect.TypeOf(m))
	if tableName == "" {
		return TableMonitor{
			Error: fmt.Errorf("object of type %s is not part of the DBModel", reflect.TypeOf(m)),
		}
	}
	return TableMonitor{
		Table:  tableName,
		Fields: fields,
	}
}

func newMonitorCookie(dbName string) MonitorCookie {
	return MonitorCookie{
		DatabaseName: dbName,
		ID:           uuid.NewString(),
	}
}

// Monitor will provide updates for a given table/column
// and populate the cache with them. Subsequent updates will be processed
// by the Update Notifications
// RFC 7047 : monitor
func (o *ovsdbClient) Monitor(ctx context.Context, options ...TableMonitor) (MonitorCookie, error) {
	cookie := newMonitorCookie(o.primaryDBName)
	return cookie, o.monitor(ctx, cookie, false, options...)
}

func (o *ovsdbClient) monitor(ctx context.Context, cookie MonitorCookie, reconnecting bool, options ...TableMonitor) error {
	if len(options) == 0 {
		return fmt.Errorf("no monitor options provided")
	}
	var reply ovsdb.TableUpdates
	dbName := cookie.DatabaseName
	db := o.databases[dbName]
	db.schemaMutex.RLock()
	mapper := mapper.NewMapper(db.schema)
	db.schemaMutex.RUnlock()
	typeMap := o.databases[dbName].model.Types()
	requests := make(map[string]ovsdb.MonitorRequest)
	for _, o := range options {
		if o.Error != nil {
			return o.Error
		}
		m, ok := typeMap[o.Table]
		if !ok {
			return fmt.Errorf("type for table %s does not exist in model", o.Table)
		}
		request, err := mapper.NewMonitorRequest(o.Table, m, o.Fields)
		if err != nil {
			return err
		}
		requests[o.Table] = *request
	}
	args := ovsdb.NewMonitorArgs(dbName, cookie, requests)

	// if we're reconnecting, we already hold the rpcMutex
	if !reconnecting {
		o.rpcMutex.RLock()
		defer o.rpcMutex.RUnlock()
	}
	if o.rpcClient == nil {
		return ErrNotConnected
	}

	err := o.rpcClient.CallWithContext(ctx, "monitor", args, &reply)
	if err != nil {
		if err == rpc2.ErrShutdown {
			return ErrNotConnected
		}
		return err
	}
	if !reconnecting {
		db := o.databases[dbName]
		db.monitorsMutex.Lock()
		db.monitors[cookie.ID] = options
		db.monitorsMutex.Unlock()
	}
	o.databases[dbName].cache.Populate(reply)
	return nil
}

// Echo tests the liveness of the OVSDB connetion
func (o *ovsdbClient) Echo(ctx context.Context) error {
	args := ovsdb.NewEchoArgs()
	var reply []interface{}
	o.rpcMutex.RLock()
	defer o.rpcMutex.RUnlock()
	if o.rpcClient == nil {
		return ErrNotConnected
	}
	err := o.rpcClient.CallWithContext(ctx, "echo", args, &reply)
	if err != nil {
		if err == rpc2.ErrShutdown {
			return ErrNotConnected
		}
	}
	if !reflect.DeepEqual(args, reply) {
		return fmt.Errorf("incorrect server response: %v, %v", args, reply)
	}
	return nil
}

// watchForLeaderChange will trigger a reconnect if the connected endpoint
// ever loses leadership
func (o *ovsdbClient) watchForLeaderChange() error {
	updates := make(chan model.Model)
	o.databases[serverDB].cache.AddEventHandler(&cache.EventHandlerFuncs{
		UpdateFunc: func(table string, _, new model.Model) {
			if table == "Database" {
				updates <- new
			}
		},
	})

	err := o.monitor(context.Background(), newMonitorCookie(serverDB), false,
		TableMonitor{
			Table: "Database",
		},
	)
	if err != nil {
		return err
	}

	go func() {
		for m := range updates {
			dbInfo, ok := m.(*serverdb.Database)
			if !ok {
				continue
			}

			// Ignore the dbInfo for _Server
			if dbInfo.Name != o.primaryDBName {
				continue
			}

			if dbInfo.Model == serverdb.DatabaseModelClustered && !dbInfo.Leader {
				log.Printf("libovsdb: endpoint %s lost leader, reconnecting", o.activeEndpoint)
				o.Disconnect()
			}
		}
	}()
	return nil
}

func (o *ovsdbClient) handleDisconnectNotification() {
	<-o.rpcClient.DisconnectNotify()
	// close the stopCh, which will stop the cache event processor
	close(o.stopCh)
	o.rpcMutex.Lock()
	if o.options.reconnect && !o.shutdown {
		o.rpcClient = nil
		o.rpcMutex.Unlock()
		connect := func() error {
			ctx, cancel := context.WithTimeout(context.Background(), o.options.timeout)
			defer cancel()
			err := o.connect(ctx, true)
			if err != nil {
				log.Printf("libovsdb: failed to reconnect: %s", err)
			}
			return err
		}
		log.Printf("libovsdb: connection to %s lost, reconnecting...", o.activeEndpoint)
		err := backoff.Retry(connect, o.options.backoff)
		if err != nil {
			// TODO: We should look at passing this back to the
			// caller to handle
			panic(err)
		}
		// this goroutine finishes, and is replaced with a new one (from Connect)
		return
	}

	// clear connection state
	o.rpcClient = nil
	o.rpcMutex.Unlock()

	for _, db := range o.databases {
		db.cacheMutex.Lock()
		defer db.cacheMutex.Unlock()
		db.cache = nil

		db.schemaMutex.Lock()
		defer db.schemaMutex.Unlock()
		db.schema = nil

		db.monitorsMutex.Lock()
		defer db.monitorsMutex.Unlock()
		db.monitors = make(map[string][]TableMonitor)
	}

	o.shutdownMutex.Lock()
	defer o.shutdownMutex.Unlock()
	o.shutdown = false

	select {
	case o.disconnect <- struct{}{}:
		// sent disconnect notification to client
	default:
		// client is not listening to the channel
	}
}

// Disconnect will close the connection to the OVSDB server
// If the client was created with WithReconnect then the client
// will reconnect afterwards
func (o *ovsdbClient) Disconnect() {
	o.rpcMutex.Lock()
	defer o.rpcMutex.Unlock()
	if o.rpcClient == nil {
		return
	}
	o.rpcClient.Close()
}

// Close will close the connection to the OVSDB server
// It will remove all stored state ready for the next connection
// Even If the client was created with WithReconnect it will not reconnect afterwards
func (o *ovsdbClient) Close() {
	o.rpcMutex.Lock()
	defer o.rpcMutex.Unlock()
	if o.rpcClient == nil {
		return
	}
	o.shutdownMutex.Lock()
	defer o.shutdownMutex.Unlock()
	o.shutdown = true
	o.rpcClient.Close()
}

// Client API interface wrapper functions
// We add this wrapper to allow users to access the API directly on the
// client object

//Get implements the API interface's Get function
func (o *ovsdbClient) Get(model model.Model) error {
	return o.primaryDB().api.Get(model)
}

//Create implements the API interface's Create function
func (o *ovsdbClient) Create(models ...model.Model) ([]ovsdb.Operation, error) {
	return o.primaryDB().api.Create(models...)
}

//List implements the API interface's List function
func (o *ovsdbClient) List(result interface{}) error {
	return o.primaryDB().api.List(result)
}

//Where implements the API interface's Where function
func (o *ovsdbClient) Where(m model.Model, conditions ...model.Condition) ConditionalAPI {
	return o.primaryDB().api.Where(m, conditions...)
}

//WhereAll implements the API interface's WhereAll function
func (o *ovsdbClient) WhereAll(m model.Model, conditions ...model.Condition) ConditionalAPI {
	return o.primaryDB().api.WhereAll(m, conditions...)
}

//WhereCache implements the API interface's WhereCache function
func (o *ovsdbClient) WhereCache(predicate interface{}) ConditionalAPI {
	return o.primaryDB().api.WhereCache(predicate)
}
