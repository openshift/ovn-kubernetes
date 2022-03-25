package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/cenkalti/rpc2"
	"github.com/cenkalti/rpc2/jsonrpc"
	"github.com/go-logr/logr"
	"github.com/go-logr/stdr"
	"github.com/google/uuid"
	"github.com/ovn-org/libovsdb/cache"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
)

// OvsdbServer is an ovsdb server
type OvsdbServer struct {
	srv          *rpc2.Server
	listener     net.Listener
	done         chan struct{}
	db           Database
	ready        bool
	readyMutex   sync.RWMutex
	models       map[string]model.DatabaseModel
	modelsMutex  sync.RWMutex
	monitors     map[*rpc2.Client]*connectionMonitors
	monitorMutex sync.RWMutex
	logger       logr.Logger
}

// NewOvsdbServer returns a new OvsdbServer
func NewOvsdbServer(db Database, models ...model.DatabaseModel) (*OvsdbServer, error) {
	l := stdr.NewWithOptions(log.New(os.Stderr, "", log.LstdFlags), stdr.Options{LogCaller: stdr.All}).WithName("server")
	stdr.SetVerbosity(5)
	o := &OvsdbServer{
		done:         make(chan struct{}, 1),
		db:           db,
		models:       make(map[string]model.DatabaseModel),
		modelsMutex:  sync.RWMutex{},
		monitors:     make(map[*rpc2.Client]*connectionMonitors),
		monitorMutex: sync.RWMutex{},
		logger:       l,
	}
	o.modelsMutex.Lock()
	for _, model := range models {
		o.models[model.Schema.Name] = model
	}
	o.modelsMutex.Unlock()
	for database, model := range o.models {
		if err := o.db.CreateDatabase(database, model.Schema); err != nil {
			return nil, err
		}
	}
	o.srv = rpc2.NewServer()
	o.srv.Handle("list_dbs", o.ListDatabases)
	o.srv.Handle("get_schema", o.GetSchema)
	o.srv.Handle("transact", o.Transact)
	o.srv.Handle("cancel", o.Cancel)
	o.srv.Handle("monitor", o.Monitor)
	o.srv.Handle("monitor_cond", o.MonitorCond)
	o.srv.Handle("monitor_cond_since", o.MonitorCondSince)
	o.srv.Handle("monitor_cancel", o.MonitorCancel)
	o.srv.Handle("steal", o.Steal)
	o.srv.Handle("unlock", o.Unlock)
	o.srv.Handle("echo", o.Echo)
	return o, nil
}

// OnConnect registers a function to run when a client connects.
func (o *OvsdbServer) OnConnect(f func(*rpc2.Client)) {
	o.srv.OnConnect(f)
}

// Serve starts the OVSDB server on the given path and protocol
func (o *OvsdbServer) Serve(protocol string, path string) error {
	var err error
	o.listener, err = net.Listen(protocol, path)
	if err != nil {
		return err
	}
	o.readyMutex.Lock()
	o.ready = true
	o.readyMutex.Unlock()
	for {
		conn, err := o.listener.Accept()
		if err != nil {
			if !o.Ready() {
				return nil
			}
			return err
		}

		// TODO: Need to cleanup when connection is closed
		go o.srv.ServeCodec(jsonrpc.NewJSONCodec(conn))
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
	}

	return false
}

// Close closes the OvsdbServer
func (o *OvsdbServer) Close() {
	o.readyMutex.Lock()
	o.ready = false
	o.readyMutex.Unlock()
	// Only close the listener if Serve() has been called
	if o.listener != nil {
		if err := o.listener.Close(); err != nil {
			o.logger.Error(err, "failed to close listener")
		}
	}
	if !isClosed(o.done) {
		close(o.done)
	}
}

// Ready returns true if a server is ready to handle connections
func (o *OvsdbServer) Ready() bool {
	o.readyMutex.RLock()
	defer o.readyMutex.RUnlock()
	return o.ready
}

// ListDatabases lists the databases in the current system
func (o *OvsdbServer) ListDatabases(client *rpc2.Client, args []interface{}, reply *[]string) error {
	dbs := []string{}
	o.modelsMutex.RLock()
	for _, db := range o.models {
		dbs = append(dbs, db.Schema.Name)
	}
	o.modelsMutex.RUnlock()
	*reply = dbs
	return nil
}

func (o *OvsdbServer) GetSchema(client *rpc2.Client, args []interface{}, reply *ovsdb.DatabaseSchema,
) error {
	db, ok := args[0].(string)
	if !ok {
		return fmt.Errorf("database %v is not a string", args[0])
	}
	o.modelsMutex.RLock()
	model, ok := o.models[db]
	if !ok {
		return fmt.Errorf("database %s does not exist", db)
	}
	o.modelsMutex.RUnlock()
	*reply = model.Schema
	return nil
}

type Transaction struct {
	ID          uuid.UUID
	Cache       *cache.TableCache
	DeletedRows map[string]struct{}
	Model       model.DatabaseModel
	DbName      string
	Database    Database
}

func (o *OvsdbServer) NewTransaction(model model.DatabaseModel, dbName string, database Database) Transaction {
	cache, err := cache.NewTableCache(dbName, model, nil, &o.logger)
	if err != nil {
		panic(err)
	}
	return Transaction{
		ID:          uuid.New(),
		Cache:       cache,
		DeletedRows: make(map[string]struct{}),
		Model:       model,
		DbName:      dbName,
		Database:    database,
	}
}

// Transact issues a new database transaction and returns the results
func (o *OvsdbServer) Transact(client *rpc2.Client, args []json.RawMessage, reply *[]ovsdb.OperationResult) error {
	if len(args) < 2 {
		return fmt.Errorf("not enough args")
	}
	var db string
	err := json.Unmarshal(args[0], &db)
	if err != nil {
		return fmt.Errorf("database %v is not a string", args[0])
	}
	if !o.db.Exists(db) {
		return fmt.Errorf("db does not exist")
	}
	var ops []ovsdb.Operation
	namedUUID := make(map[string]ovsdb.UUID)
	for i := 1; i < len(args); i++ {
		var op ovsdb.Operation
		err = json.Unmarshal(args[i], &op)
		if err != nil {
			return err
		}
		if op.UUIDName != "" {
			newUUID := uuid.NewString()
			namedUUID[op.UUIDName] = ovsdb.UUID{GoUUID: newUUID}
			op.UUIDName = newUUID
		}
		for i, condition := range op.Where {
			op.Where[i].Value = expandNamedUUID(condition.Value, namedUUID)
		}
		for i, mutation := range op.Mutations {
			op.Mutations[i].Value = expandNamedUUID(mutation.Value, namedUUID)
		}
		for _, row := range op.Rows {
			for k, v := range row {
				row[k] = expandNamedUUID(v, namedUUID)
			}
		}
		for k, v := range op.Row {
			op.Row[k] = expandNamedUUID(v, namedUUID)
		}
		ops = append(ops, op)
	}
	response, updates := o.transact(db, ops)
	*reply = response
	transactionID := uuid.New()
	o.processMonitors(transactionID, updates)
	return o.db.Commit(db, transactionID, updates)
}

func deepCopy(a ovsdb.TableUpdates) (ovsdb.TableUpdates, error) {
	var b ovsdb.TableUpdates
	raw, err := json.Marshal(a)
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(raw, &b)
	return b, err
}

func deepCopy2(a ovsdb.TableUpdates2) (ovsdb.TableUpdates2, error) {
	var b ovsdb.TableUpdates2
	raw, err := json.Marshal(a)
	if err != nil {
		return b, err
	}
	err = json.Unmarshal(raw, &b)
	return b, err
}

// Cancel cancels the last transaction
func (o *OvsdbServer) Cancel(client *rpc2.Client, args []interface{}, reply *[]interface{}) error {
	return fmt.Errorf("not implemented")
}

// Monitor monitors a given database table and provides updates to the client via an RPC callback
func (o *OvsdbServer) Monitor(client *rpc2.Client, args []json.RawMessage, reply *ovsdb.TableUpdates) error {
	var db string
	if err := json.Unmarshal(args[0], &db); err != nil {
		return fmt.Errorf("database %v is not a string", args[0])
	}
	if !o.db.Exists(db) {
		return fmt.Errorf("db does not exist")
	}
	value := string(args[1])
	var request map[string]*ovsdb.MonitorRequest
	if err := json.Unmarshal(args[2], &request); err != nil {
		return err
	}
	o.monitorMutex.Lock()
	defer o.monitorMutex.Unlock()
	clientMonitors, ok := o.monitors[client]
	if !ok {
		o.monitors[client] = newConnectionMonitors()
	} else {
		if _, ok := clientMonitors.monitors[value]; ok {
			return fmt.Errorf("monitor with that value already exists")
		}
	}

	o.modelsMutex.Lock()
	dbModel := o.models[db]
	o.modelsMutex.Unlock()
	transaction := o.NewTransaction(dbModel, db, o.db)

	tableUpdates := make(ovsdb.TableUpdates)
	for t, request := range request {
		rows := transaction.Select(t, nil, request.Columns)
		for i := range rows.Rows {
			tu := make(ovsdb.TableUpdate)
			uuid := rows.Rows[i]["_uuid"].(ovsdb.UUID).GoUUID
			tu[uuid] = &ovsdb.RowUpdate{
				New: &rows.Rows[i],
			}
			tableUpdates.AddTableUpdate(t, tu)
		}
	}
	*reply = tableUpdates
	o.monitors[client].monitors[value] = newMonitor(value, request, client)
	return nil
}

// MonitorCond monitors a given database table and provides updates to the client via an RPC callback
func (o *OvsdbServer) MonitorCond(client *rpc2.Client, args []json.RawMessage, reply *ovsdb.TableUpdates2) error {
	var db string
	if err := json.Unmarshal(args[0], &db); err != nil {
		return fmt.Errorf("database %v is not a string", args[0])
	}
	if !o.db.Exists(db) {
		return fmt.Errorf("db does not exist")
	}
	value := string(args[1])
	var request map[string]*ovsdb.MonitorRequest
	if err := json.Unmarshal(args[2], &request); err != nil {
		return err
	}
	o.monitorMutex.Lock()
	defer o.monitorMutex.Unlock()
	clientMonitors, ok := o.monitors[client]
	if !ok {
		o.monitors[client] = newConnectionMonitors()
	} else {
		if _, ok := clientMonitors.monitors[value]; ok {
			return fmt.Errorf("monitor with that value already exists")
		}
	}

	o.modelsMutex.Lock()
	dbModel := o.models[db]
	o.modelsMutex.Unlock()
	transaction := o.NewTransaction(dbModel, db, o.db)

	tableUpdates := make(ovsdb.TableUpdates2)
	for t, request := range request {
		rows := transaction.Select(t, nil, request.Columns)
		for i := range rows.Rows {
			tu := make(ovsdb.TableUpdate2)
			uuid := rows.Rows[i]["_uuid"].(ovsdb.UUID).GoUUID
			tu[uuid] = &ovsdb.RowUpdate2{Initial: &rows.Rows[i]}
			tableUpdates.AddTableUpdate(t, tu)
		}
	}
	*reply = tableUpdates
	o.monitors[client].monitors[value] = newConditionalMonitor(value, request, client)
	return nil
}

// MonitorCondSince monitors a given database table and provides updates to the client via an RPC callback
func (o *OvsdbServer) MonitorCondSince(client *rpc2.Client, args []json.RawMessage, reply *ovsdb.MonitorCondSinceReply) error {
	var db string
	if err := json.Unmarshal(args[0], &db); err != nil {
		return fmt.Errorf("database %v is not a string", args[0])
	}
	if !o.db.Exists(db) {
		return fmt.Errorf("db does not exist")
	}
	value := string(args[1])
	var request map[string]*ovsdb.MonitorRequest
	if err := json.Unmarshal(args[2], &request); err != nil {
		return err
	}
	o.monitorMutex.Lock()
	defer o.monitorMutex.Unlock()
	clientMonitors, ok := o.monitors[client]
	if !ok {
		o.monitors[client] = newConnectionMonitors()
	} else {
		if _, ok := clientMonitors.monitors[value]; ok {
			return fmt.Errorf("monitor with that value already exists")
		}
	}

	o.modelsMutex.Lock()
	dbModel := o.models[db]
	o.modelsMutex.Unlock()
	transaction := o.NewTransaction(dbModel, db, o.db)

	tableUpdates := make(ovsdb.TableUpdates2)
	for t, request := range request {
		rows := transaction.Select(t, nil, request.Columns)
		for i := range rows.Rows {
			tu := make(ovsdb.TableUpdate2)
			uuid := rows.Rows[i]["_uuid"].(ovsdb.UUID).GoUUID
			tu[uuid] = &ovsdb.RowUpdate2{Initial: &rows.Rows[i]}
			tableUpdates.AddTableUpdate(t, tu)
		}
	}
	*reply = ovsdb.MonitorCondSinceReply{Found: false, LastTransactionID: "00000000-0000-0000-000000000000", Updates: tableUpdates}
	o.monitors[client].monitors[value] = newConditionalSinceMonitor(value, request, client)
	return nil
}

// MonitorCancel cancels a monitor on a given table
func (o *OvsdbServer) MonitorCancel(client *rpc2.Client, args []interface{}, reply *[]interface{}) error {
	return fmt.Errorf("not implemented")
}

// Lock acquires a lock on a table for a the client
func (o *OvsdbServer) Lock(client *rpc2.Client, args []interface{}, reply *[]interface{}) error {
	return fmt.Errorf("not implemented")
}

// Steal steals a lock for a client
func (o *OvsdbServer) Steal(client *rpc2.Client, args []interface{}, reply *[]interface{}) error {
	return fmt.Errorf("not implemented")
}

// Unlock releases a lock for a client
func (o *OvsdbServer) Unlock(client *rpc2.Client, args []interface{}, reply *[]interface{}) error {
	return fmt.Errorf("not implemented")
}

// Echo tests the liveness of the connection
func (o *OvsdbServer) Echo(client *rpc2.Client, args []interface{}, reply *[]interface{}) error {
	echoReply := make([]interface{}, len(args))
	copy(echoReply, args)
	*reply = echoReply
	return nil
}

func (o *OvsdbServer) processMonitors(id uuid.UUID, update ovsdb.TableUpdates2) {
	o.monitorMutex.RLock()
	for _, c := range o.monitors {
		for _, m := range c.monitors {
			switch m.kind {
			case monitorKindOriginal:
				var updates ovsdb.TableUpdates
				updates.FromTableUpdates2(update)
				// Deep copy for every monitor since each one filters
				// the update for relevant tables and removes items
				// from the update array
				dbUpdates, _ := deepCopy(updates)
				m.Send(dbUpdates)
			case monitorKindConditional:
				dbUpdates, _ := deepCopy2(update)
				m.Send2(dbUpdates)
			case monitorKindConditionalSince:
				dbUpdates, _ := deepCopy2(update)
				m.Send3(id, dbUpdates)
			}
		}
	}
	o.monitorMutex.RUnlock()
}

func expandNamedUUID(value interface{}, namedUUID map[string]ovsdb.UUID) interface{} {
	if uuid, ok := value.(ovsdb.UUID); ok {
		if newUUID, ok := namedUUID[uuid.GoUUID]; ok {
			return newUUID
		}
	}
	if set, ok := value.(ovsdb.OvsSet); ok {
		for i, s := range set.GoSet {
			if _, ok := s.(ovsdb.UUID); !ok {
				return value
			}
			uuid := s.(ovsdb.UUID)
			if newUUID, ok := namedUUID[uuid.GoUUID]; ok {
				set.GoSet[i] = newUUID
			}
		}
	}
	if m, ok := value.(ovsdb.OvsMap); ok {
		for k, v := range m.GoMap {
			if uuid, ok := v.(ovsdb.UUID); ok {
				if newUUID, ok := namedUUID[uuid.GoUUID]; ok {
					m.GoMap[k] = newUUID
				}
			}
			if uuid, ok := k.(ovsdb.UUID); ok {
				if newUUID, ok := namedUUID[uuid.GoUUID]; ok {
					m.GoMap[newUUID] = m.GoMap[k]
					delete(m.GoMap, uuid)
				}
			}
		}
	}
	return value
}
