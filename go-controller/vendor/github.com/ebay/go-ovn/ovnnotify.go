/**
 * Copyright (c) 2017 eBay Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 **/

package goovn

import (
	"sync"

	"k8s.io/klog/v2"

	"github.com/ebay/libovsdb"
)

type ovnNotifier struct {
	odbi *ovndb
}

type deferredUpdate struct {
	db       string
	updates  *libovsdb.TableUpdates
	updates2 *libovsdb.TableUpdates2
}

// maybeDeferUpdate returns true if the update was deferred
func (notify ovnNotifier) maybeDeferUpdate(db string, updates *libovsdb.TableUpdates, updates2 *libovsdb.TableUpdates2) bool {
	if !notify.odbi.connecting {
		return false
	}
	notify.odbi.deferredUpdates = append(notify.odbi.deferredUpdates, &deferredUpdate{
		db:       db,
		updates:  updates,
		updates2: updates2,
	})
	return true
}

func (notify ovnNotifier) getDBNameAndLock(context interface{}) (string, *sync.RWMutex) {
	dbName, ok := context.(string)
	if !ok {
		klog.Warningf("Expected string-type context but got %v", context)
		return "", nil
	}

	if dbName == DBServer {
		return dbName, &notify.odbi.serverCacheMutex
	}

	return dbName, &notify.odbi.cachemutex
}

func (notify ovnNotifier) Update(context interface{}, tableUpdates libovsdb.TableUpdates) {
	db, lock := notify.getDBNameAndLock(context)

	if !notify.maybeDeferUpdate(db, &tableUpdates, nil) {
		if lock != nil {
			lock.Lock()
			defer lock.Unlock()
			notify.odbi.populateCache(db, tableUpdates, true)
		}
	}
}
func (notify ovnNotifier) Update2(context interface{}, tableUpdates libovsdb.TableUpdates2) {
	db, lock := notify.getDBNameAndLock(context)

	if !notify.maybeDeferUpdate(db, nil, &tableUpdates) {
		if lock != nil {
			lock.Lock()
			defer lock.Unlock()
			notify.odbi.populateCache2(db, tableUpdates, true)
		}
	}
}

func (notify ovnNotifier) Update3(context interface{}, tableUpdates libovsdb.TableUpdates2, lastTxnId string) {
	db, lock := notify.getDBNameAndLock(context)

	if !notify.maybeDeferUpdate(db, nil, &tableUpdates) {
		if lock != nil {
			lock.Lock()
			defer lock.Unlock()
			notify.odbi.populateCache2(db, tableUpdates, true)
			notify.odbi.currentTxn = lastTxnId
		}
	}
}

func (notify ovnNotifier) Locked([]interface{}) {
}
func (notify ovnNotifier) Stolen([]interface{}) {
}
func (notify ovnNotifier) Echo([]interface{}) {
}

func (notify ovnNotifier) Disconnected(client *libovsdb.OvsdbClient) {
	if notify.odbi.reconn {
		notify.odbi.reconnect()
	} else if notify.odbi.disconnectCB != nil {
		notify.odbi.disconnectCB()
	}
}
