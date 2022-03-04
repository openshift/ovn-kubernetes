package server

import (
	"fmt"
	"sync"

	"github.com/google/uuid"
	"github.com/ovn-org/libovsdb/cache"
	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/libovsdb/ovsdb"
)

// Database abstracts database operations from ovsdb
type Database interface {
	CreateDatabase(database string, model ovsdb.DatabaseSchema) error
	Exists(database string) bool
	Commit(database string, id uuid.UUID, updates ovsdb.TableUpdates2) error
	CheckIndexes(database string, table string, m model.Model) error
	List(database, table string, conditions ...ovsdb.Condition) (map[string]model.Model, error)
	Get(database, table string, uuid string) (model.Model, error)
}

type inMemoryDatabase struct {
	databases map[string]*cache.TableCache
	models    map[string]model.ClientDBModel
	mutex     sync.RWMutex
}

func NewInMemoryDatabase(models map[string]model.ClientDBModel) Database {
	return &inMemoryDatabase{
		databases: make(map[string]*cache.TableCache),
		models:    models,
		mutex:     sync.RWMutex{},
	}
}

func (db *inMemoryDatabase) CreateDatabase(name string, schema ovsdb.DatabaseSchema) error {
	db.mutex.Lock()
	defer db.mutex.Unlock()
	var mo model.ClientDBModel
	var ok bool
	if mo, ok = db.models[schema.Name]; !ok {
		return fmt.Errorf("no db model provided for schema with name %s", name)
	}
	dbModel, errs := model.NewDatabaseModel(schema, mo)
	if len(errs) > 0 {
		return fmt.Errorf("failed to create DatabaseModel: %#+v", errs)
	}
	database, err := cache.NewTableCache(name, dbModel, nil, nil)
	if err != nil {
		return err
	}
	db.databases[name] = database
	return nil
}

func (db *inMemoryDatabase) Exists(name string) bool {
	db.mutex.RLock()
	defer db.mutex.RUnlock()
	_, ok := db.databases[name]
	return ok
}

func (db *inMemoryDatabase) Commit(database string, id uuid.UUID, updates ovsdb.TableUpdates2) error {
	if !db.Exists(database) {
		return fmt.Errorf("db does not exist")
	}
	db.mutex.RLock()
	targetDb := db.databases[database]
	db.mutex.RLock()
	return targetDb.Populate2(updates)
}

func (db *inMemoryDatabase) CheckIndexes(database string, table string, m model.Model) error {
	if !db.Exists(database) {
		return nil
	}
	db.mutex.RLock()
	targetDb := db.databases[database]
	db.mutex.RLock()
	targetTable := targetDb.Table(table)
	return targetTable.IndexExists(m)
}

func (db *inMemoryDatabase) List(database, table string, conditions ...ovsdb.Condition) (map[string]model.Model, error) {
	if !db.Exists(database) {
		return nil, fmt.Errorf("db does not exist")
	}
	db.mutex.RLock()
	targetDb := db.databases[database]
	db.mutex.RLock()

	targetTable := targetDb.Table(table)
	if targetTable == nil {
		return nil, fmt.Errorf("table does not exist")
	}

	return targetTable.RowsByCondition(conditions)
}

func (db *inMemoryDatabase) Get(database, table string, uuid string) (model.Model, error) {
	if !db.Exists(database) {
		return nil, fmt.Errorf("db does not exist")
	}
	db.mutex.RLock()
	targetDb := db.databases[database]
	db.mutex.RLock()

	targetTable := targetDb.Table(table)
	if targetTable == nil {
		return nil, fmt.Errorf("table does not exist")
	}
	return targetTable.Row(uuid), nil
}
