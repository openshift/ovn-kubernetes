package ovn

import (
	"fmt"
	"net"
	"sync"
	"time"

	addressset "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/ovn/address_set"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/klog/v2"
)

type EgressDNS struct {
	// Protects pdMap/namespaces operations
	lock sync.Mutex
	// holds DNS entries globally
	dns *util.DNS
	// this map holds dnsNames to the dnsEntries
	dnsEntries map[string]*dnsEntry
	// allows for the creation of addresssets
	addressSetFactory addressset.AddressSetFactory

	// Report change when Add operation is done
	added          chan struct{}
	deleted        chan string
	stopChan       chan struct{}
	controllerStop <-chan struct{}
}

type dnsEntry struct {
	// this map holds all the namespaces that a dnsName appears in
	namespaces map[string]struct{}
	// the current IP addresses the dnsName resolves to
	// NOTE: used for testing
	dnsResolves []net.IP
	// the addressSet that contains the current IPs
	dnsAddressSet addressset.AddressSet
}

func NewEgressDNS(addressSetFactory addressset.AddressSetFactory, controllerStop <-chan struct{}) (*EgressDNS, error) {
	dnsInfo, err := util.NewDNS("/etc/resolv.conf")
	if err != nil {
		return nil, err
	}

	egressDNS := &EgressDNS{
		dns:               dnsInfo,
		dnsEntries:        make(map[string]*dnsEntry),
		addressSetFactory: addressSetFactory,

		added:          make(chan struct{}),
		deleted:        make(chan string, 1),
		stopChan:       make(chan struct{}),
		controllerStop: controllerStop,
	}

	return egressDNS, nil
}

func (e *EgressDNS) Add(namespace, dnsName string) (addressset.AddressSet, error) {
	e.lock.Lock()
	defer e.lock.Unlock()

	if _, exists := e.dnsEntries[dnsName]; !exists {
		var err error
		dnsEntry := dnsEntry{
			namespaces: make(map[string]struct{}),
		}
		if e.addressSetFactory == nil {
			return nil, fmt.Errorf("error adding EgressFirewall DNS rule for host %s, in namespace %s: addressSetFactory is nil", dnsName, namespace)
		}
		dnsEntry.dnsAddressSet, err = e.addressSetFactory.NewAddressSet(dnsName, nil)
		if err != nil {
			return nil, fmt.Errorf("cannot create addressSet for %s: %v", dnsName, err)
		}
		e.dnsEntries[dnsName] = &dnsEntry
		go e.addToDNS(dnsName)
	}
	e.dnsEntries[dnsName].namespaces[namespace] = struct{}{}
	return e.dnsEntries[dnsName].dnsAddressSet, nil

}

func (e *EgressDNS) Delete(namespace string) bool {
	e.lock.Lock()
	var dnsNamesToDelete []string

	// go through all dnsNames for namespaces
	for dnsName, dnsEntry := range e.dnsEntries {
		// delete the dnsEntry
		delete(dnsEntry.namespaces, namespace)
		if len(dnsEntry.namespaces) == 0 {
			// the dnsEntry appears in no other namespace, so delete the address_set
			err := dnsEntry.dnsAddressSet.Destroy()
			if err != nil {
				klog.Errorf("Error deleting EgressFirewall AddressSet for dnsName: %s %v", dnsName, err)
			}
			// the dnsEntry is no longer needed because nothing references it, so delete it
			delete(e.dnsEntries, dnsName)
			dnsNamesToDelete = append(dnsNamesToDelete, dnsName)
		}
	}
	e.lock.Unlock()
	for _, name := range dnsNamesToDelete {
		e.dns.Delete(name)
		// send a message to the "deleted" buffered channel so that Run() stops using
		// the deleted domain name. (channel is buffered so that sending values to it
		// blocks only if Run() is busy updating its internal values)
		e.deleted <- name
	}
	return len(e.dnsEntries) == 0
}

func (e *EgressDNS) Update(dns string) (bool, error) {
	return e.dns.Update(dns)
}

func (e *EgressDNS) updateEntryForName(dnsName string) error {
	e.lock.Lock()
	defer e.lock.Unlock()
	ips := e.dns.GetIPs(dnsName)
	if _, ok := e.dnsEntries[dnsName]; !ok {
		return fmt.Errorf("cannot update DNS record for %s: no entry found. "+
			"Was the EgressFirewall deleted?", dnsName)
	}
	e.dnsEntries[dnsName].dnsResolves = ips

	if err := e.dnsEntries[dnsName].dnsAddressSet.SetIPs(ips); err != nil {
		return fmt.Errorf("cannot add IPs from EgressFirewall AddressSet %s: %v", dnsName, err)
	}
	return nil
}

// addToDNS takes the dnsName adds it to the underlying dns resolver and
// performs the first update. After completing that signals the
// thread performing periodic updates that a new DNS name has been added and
// so that it can updates GetNextQueryTime() if needed
func (e *EgressDNS) addToDNS(dnsName string) {
	if err := e.dns.Add(dnsName); err != nil {
		utilruntime.HandleError(err)
	}
	if err := e.updateEntryForName(dnsName); err != nil {
		utilruntime.HandleError(err)
	}
	// No need to block waiting to signal the add.
	select {
	case e.added <- struct{}{}:
		klog.V(5).Infof("Recalculation of next query time requested")
	default:
		klog.V(5).Infof("Recalculation of next query time already requested")
	}
}

// Run spawns a goroutine that handles updates to the dns entries for dnsNames used in
// EgressFirewalls. The loop runs after receiving one of three signals:
// 1. time.After(durationTillNextQuery) times out and the dnsName with the lowest ttl is checked
//    and the durationTillNextQuery is updated
// 2. e.added is received and durationTillNextQuery is recomputed
// 3. e.deleted is received and coincides with dnsName
func (e *EgressDNS) Run(defaultInterval time.Duration) {
	var dnsName, dnsNameDeleted string
	var ttl time.Time
	var timeSet bool
	// initially the next DNS Query happens at the default interval
	durationTillNextQuery := defaultInterval
	go func() {
		for {
			// perform periodic updates on dnsNames as each ttl runs out, checking for updates at
			// least every defaultInterval. Update durationTillNextQuery everytime a new DNS name gets
			// added
			select {
			case <-e.added:
				//on update need to check if the GetNextQueryTime has changed
			case <-time.After(durationTillNextQuery):
				if len(dnsName) > 0 {
					if _, err := e.Update(dnsName); err != nil {
						utilruntime.HandleError(err)
					}
					if err := e.updateEntryForName(dnsName); err != nil {
						utilruntime.HandleError(err)
					}
				}
			case dnsNameDeleted = <-e.deleted:
				// Break from the select and update dnsName only if dnsName
				// appears in an EgressFirewall that has just been deleted.
				if dnsName != dnsNameDeleted {
					continue
				}
			case <-e.stopChan:
				return
			case <-e.controllerStop:
				return
			}

			// before waiting on the signals get the next time this thread needs to wake up
			ttl, dnsName, timeSet = e.dns.GetNextQueryTime()
			if time.Until(ttl) > defaultInterval || !timeSet {
				durationTillNextQuery = defaultInterval
			} else {
				durationTillNextQuery = time.Until(ttl)
			}
		}
	}()

}

func (e *EgressDNS) Shutdown() {
	close(e.stopChan)
}
