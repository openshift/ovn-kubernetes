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
	"log"

	"github.com/ebay/libovsdb"
)

type ovnNotifier struct {
	odbi *ovndb
}

func (notify ovnNotifier) Update(context interface{}, tableUpdates libovsdb.TableUpdates) {
	dbName, ok := context.(string)
	if !ok {
		log.Printf("invalid Update context %v", context)
		return
	}
	if dbName == DBServer {
		notify.odbi.serverCacheMutex.Lock()
		defer notify.odbi.serverCacheMutex.Unlock()
	} else {
		notify.odbi.cachemutex.Lock()
		defer notify.odbi.cachemutex.Unlock()
	}
	notify.odbi.populateCache(context, tableUpdates, true)
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
