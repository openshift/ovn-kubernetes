package addressset

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pkg/errors"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"

	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
)

const (
	ipv4AddressSetSuffix = "_v4"
	ipv6AddressSetSuffix = "_v6"
)

type AddressSetIterFunc func(hashedName, namespace, suffix string)
type AddressSetDoFunc func(as AddressSet) error

// AddressSetFactory is an interface for managing address set objects
type AddressSetFactory interface {
	// NewAddressSet returns a new object that implements AddressSet
	// and contains the given IPs, or an error. Internally it creates
	// an address set for IPv4 and IPv6 each.
	NewAddressSet(name string, ips []net.IP) (AddressSet, error)
	// EnsureAddressSet makes sure that an address set object exists in ovn
	// with the given name
	EnsureAddressSet(name string) error
	// ProcessEachAddressSet calls the given function for each address set
	// known to the factory
	ProcessEachAddressSet(iteratorFn AddressSetIterFunc) error
	// DestroyAddressSetInBackingStore deletes the named address set from the
	// factory's backing store. SHOULD NOT BE CALLED for any address set
	// for which an AddressSet object has been created.
	DestroyAddressSetInBackingStore(name string) error
}

// AddressSet is an interface for address set objects
type AddressSet interface {
	// GetASHashName returns the hashed name for ipv6 and ipv4 addressSets
	GetASHashNames() (string, string)
	// GetName returns the descriptive name of the address set
	GetName() string
	// AddIPs adds the array of IPs to the address set
	AddIPs(ip []net.IP) (time.Duration, time.Duration, error)
	// SetIPs sets the address set to the given array of addresses
	SetIPs(ip []net.IP) error
	DeleteIPs(ip []net.IP) error
	Destroy() error
}

type ovnAddressSetFactory struct{}

// NewOvnAddressSetFactory creates a new AddressSetFactory backed by
// address set objects that execute OVN commands
func NewOvnAddressSetFactory() AddressSetFactory {
	return &ovnAddressSetFactory{}
}

// ovnAddressSetFactory implements the AddressSetFactory interface
var _ AddressSetFactory = &ovnAddressSetFactory{}

// NewAddressSet returns a new address set object
func (asf *ovnAddressSetFactory) NewAddressSet(name string, ips []net.IP) (AddressSet, error) {
	res, err := newOvnAddressSets(name, ips)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// EnsureAddressSet ensures the address_set with the given name exists and if it does not creates an empty addressSet
func (asf *ovnAddressSetFactory) EnsureAddressSet(name string) error {
	hashedAddressSetNames := []string{}
	ip4ASName, ip6ASName := MakeAddressSetName(name)
	if config.IPv4Mode {
		hashedAddressSetNames = append(hashedAddressSetNames, ip4ASName)
	}
	if config.IPv6Mode {
		hashedAddressSetNames = append(hashedAddressSetNames, ip6ASName)
	}
	for _, hashedAddressSetName := range hashedAddressSetNames {
		uuid, stderr, err := util.RunOVNNbctl(
			"--data=bare",
			"--no-heading",
			"--columns=_uuid",
			"find",
			"address_set",
			"name="+hashedAddressSetName)
		if err != nil {
			return fmt.Errorf("find failed to get address set %q, stderr: %q (%v)",
				name, stderr, err)
		}
		if uuid != "" {
			// address_set already exists
			continue
		}
		// create the address_set with no IPs
		_, stderr, err = util.RunOVNNbctl(
			"create",
			"address_set",
			"name="+hashedAddressSetName,
			"external-ids:name="+name,
		)
		if err != nil {
			return fmt.Errorf("failed to create address set %q, stderr: %q (%v)",
				name, stderr, err)
		}

	}

	return nil
}

func forEachAddressSet(do func(string)) error {
	output, stderr, err := util.RunOVNNbctl("--format=csv", "--data=bare", "--no-heading",
		"--columns=external_ids", "find", "address_set")
	if err != nil {
		return fmt.Errorf("error reading address sets: "+
			"stdout: %q, stderr: %q err: %v", output, stderr, err)
	}

	for _, line := range strings.Split(output, "\n") {
		for _, externalID := range strings.Split(line, ",") {
			if !strings.HasPrefix(externalID, "name=") {
				continue
			}
			name := externalID[5:]
			do(name)
			break
		}
	}
	return nil
}

// ProcessEachAddressSet will pass the unhashed address set name, namespace name
// and the first suffix in the name to the 'iteratorFn' for every address_set in
// OVN. (Unhashed address set names are of the form namespaceName[.suffix1.suffix2. .suffixN])
func (asf *ovnAddressSetFactory) ProcessEachAddressSet(iteratorFn AddressSetIterFunc) error {
	processedAddressSets := sets.String{}
	err := forEachAddressSet(func(name string) {
		// Remove the suffix from the address set name and normalize
		addrSetName := truncateSuffixFromAddressSet(name)
		if processedAddressSets.Has(addrSetName) {
			// We have already processed the address set. In case of dual stack we will have _v4 and _v6
			// suffixes for address sets. Since we are normalizing these two address sets through this API
			// we will process only one normalized address set name.
			return
		}
		processedAddressSets.Insert(addrSetName)
		names := strings.Split(addrSetName, ".")
		addrSetNamespace := names[0]
		nameSuffix := ""
		if len(names) >= 2 {
			nameSuffix = names[1]
		}
		iteratorFn(addrSetName, addrSetNamespace, nameSuffix)
	})

	return err
}

func truncateSuffixFromAddressSet(asName string) string {
	// Legacy address set names will not have v4 or v6 suffixes.
	// truncate them for the new ones
	if strings.HasSuffix(asName, ipv4AddressSetSuffix) {
		return strings.TrimSuffix(asName, ipv4AddressSetSuffix)
	}
	if strings.HasSuffix(asName, ipv6AddressSetSuffix) {
		return strings.TrimSuffix(asName, ipv6AddressSetSuffix)
	}
	return asName
}

// DestroyAddressSetInBackingStore ensures an address set is deleted
func (asf *ovnAddressSetFactory) DestroyAddressSetInBackingStore(name string) error {
	// We need to handle both legacy and new address sets in this method. Legacy names
	// will not have v4 and v6 suffix as they were same as namespace name. Hence we will always try to destroy
	// the address set with raw name(namespace name), v4 name and v6 name.  The method destroyAddressSet uses
	// --if-exists parameter which will take care of deleting the address set only if it exists.
	err := destroyAddressSet(name)
	if err != nil {
		return err
	}
	ip4ASName, ip6ASName := MakeAddressSetName(name)
	err = destroyAddressSet(ip4ASName)
	if err != nil {
		return err
	}
	err = destroyAddressSet(ip6ASName)
	if err != nil {
		return err
	}
	return nil
}

func destroyAddressSet(name string) error {
	hashName := hashedAddressSet(name)
	_, stderr, err := util.RunOVNNbctl("--if-exists", "destroy", "address_set", hashName)
	if err != nil {
		return fmt.Errorf("failed to destroy address set %q, stderr: %q, (%v)",
			hashName, stderr, err)
	}
	return nil
}

type ovnAddressSet struct {
	name     string
	hashName string
	uuid     string
	ips      map[string]net.IP
	stopCh   chan bool
	ops      chan *addrOp
	doneWg   *sync.WaitGroup
}

type addrOpType uint

const (
	addrOpAdd = iota
	addrOpDel
	addrOpSet
	addrOpClear
)

type addrOp struct {
	ips []net.IP
	op  addrOpType
}

type ovnAddressSets struct {
	sync.RWMutex
	name string
	ipv4 *ovnAddressSet
	ipv6 *ovnAddressSet
}

// ovnAddressSets implements the AddressSet interface
var _ AddressSet = &ovnAddressSets{}

// hash the provided input to make it a valid ovnAddressSet name.
func hashedAddressSet(s string) string {
	return util.HashForOVN(s)
}

func asDetail(as *ovnAddressSet) string {
	return fmt.Sprintf("%s/%s/%s", as.uuid, as.name, as.hashName)
}

func newOvnAddressSets(name string, ips []net.IP) (*ovnAddressSets, error) {
	var (
		v4set, v6set *ovnAddressSet
		err          error
	)
	v4IPs, v6IPs := splitIPsByFamily(ips)

	ip4ASName, ip6ASName := MakeAddressSetName(name)
	if config.IPv4Mode {
		v4set, err = newOvnAddressSet(ip4ASName, v4IPs)
		if err != nil {
			return nil, err
		}
	}
	if config.IPv6Mode {
		v6set, err = newOvnAddressSet(ip6ASName, v6IPs)
		if err != nil {
			return nil, err
		}
	}
	return &ovnAddressSets{name: name, ipv4: v4set, ipv6: v6set}, nil
}

func (as *ovnAddressSet) runBatch(ops []*addrOp) {
	if len(ops) == 0 {
		return
	}

	newOps := make([]*addrOp, 0, len(ops))
	var lastOp *addrOp
	for _, op := range ops {
		if op.op == addrOpSet || op.op == addrOpClear {
			// set or clear discards all earlier ops
			newOps = []*addrOp{op}
		} else if lastOp != nil && lastOp.op == op.op {
			// Same type as previous, just add new ips to previous op
			lastOp.ips = append(lastOp.ips, op.ips...)
		} else {
			// New op
			newOps = append(newOps, op)
		}
	}

	txn := util.NewNBTxn()
	for _, op := range newOps {
		switch op.op {
		case addrOpClear:
			request := []string{"clear", "address_set", as.uuid, "addresses"}
			if _, stderr, err := txn.AddOrCommit(request); err != nil {
				klog.Errorf("failed to clear address set %q, stderr: %q (%v)",
					asDetail(as), stderr, err)
			} else {
				as.ips = make(map[string]net.IP, 5)
			}
		case addrOpSet:
			ipStr := joinIPs(op.ips)
			request := []string{"set", "address_set", as.uuid, "addresses="+ipStr}
			if _, stderr, err := txn.AddOrCommit(request); err != nil {
				klog.Errorf("failed to set address set %q to %q, stderr: %q (%v)",
					asDetail(as), ipStr, stderr, err)
			} else {
				as.ips = make(map[string]net.IP, len(op.ips))
				for _, ip := range op.ips {
					as.ips[ip.String()] = ip
				}
			}
		case addrOpAdd:
			uniqIPs := make([]net.IP, 0, len(op.ips))
			for _, ip := range op.ips {
				if _, ok := as.ips[ip.String()]; !ok {
					uniqIPs = append(uniqIPs, ip)
				}
			}
			if len(uniqIPs) > 0 {
				ipStr := joinIPs(op.ips)
				request := []string{"add", "address_set", as.uuid, "addresses", ipStr}
				if _, stderr, err := txn.AddOrCommit(request); err != nil {
					klog.Errorf("failed to add IPs (%q) to address set %q, stderr: %q (%v)",
						ipStr, asDetail(as), stderr, err)
				} else {
					for _, ip := range op.ips {
						as.ips[ip.String()] = ip
					}
				}
			}
		case addrOpDel:
			uniqIPs := make([]net.IP, 0, len(op.ips))
			for _, ip := range op.ips {
				if _, ok := as.ips[ip.String()]; !ok {
					continue
				}
				uniqIPs = append(uniqIPs, ip)
			}
			if len(uniqIPs) > 0 {
				ipStr := joinIPs(uniqIPs)
				request := []string{"remove", "address_set", as.uuid, "addresses", ipStr}
				if _, stderr, err := txn.AddOrCommit(request); err != nil {
					klog.Errorf("failed to remove IPs %q from address set %q, stderr: %q (%v)",
						ipStr, asDetail(as), stderr, err)
				} else {
					for _, ip := range uniqIPs {
						delete(as.ips, ip.String())
					}
				}
			}
		}
	}

	if stdout, stderr, err := txn.Commit(); err != nil {
		klog.Errorf("Error updating address set %q: stdout: %q, stderr: %q, error: %v",
			asDetail(as), stdout, stderr, err)
	}
}

func newOvnAddressSet(name string, ips []net.IP) (*ovnAddressSet, error) {
	as := &ovnAddressSet{
		name:     name,
		hashName: hashedAddressSet(name),
		ips:      make(map[string]net.IP),
		ops:      make(chan *addrOp),
		stopCh:   make(chan bool),
		doneWg:   &sync.WaitGroup{},
	}
	for _, ip := range ips {
		as.ips[ip.String()] = ip
	}

	uuid, stderr, err := util.RunOVNNbctl("--data=bare",
		"--no-heading", "--columns=_uuid", "find", "address_set",
		"name="+as.hashName)
	if err != nil {
		return nil, fmt.Errorf("find failed to get address set %q, stderr: %q (%v)",
			as.name, stderr, err)
	}
	as.uuid = uuid

	// Start processing update batches
	startWg := &sync.WaitGroup{}
	startWg.Add(1)
	as.doneWg.Add(1)
	go func() {
		startWg.Done()
		defer as.doneWg.Done()
		items := make([]*addrOp, 0, 5)
		for {
			select {
			case op, ok := <-as.ops:
				if !ok {
					return
				}
				items = append(items, op)

			case <-time.After(10 * time.Millisecond):
				as.runBatch(items)
				items = make([]*addrOp, 0, 5)

			case <-as.stopCh:
				as.runBatch(items)
				return
			}
		}
	}()
	startWg.Wait()

	if uuid != "" {
		klog.V(5).Infof("New(%s) already exists; updating IPs", asDetail(as))
		// ovnAddressSet already exists in the database; just update IPs
		if err := as.setIPs(ips); err != nil {
			return nil, err
		}
	} else {
		// ovnAddressSet has not been created yet. Create it.
		args := []string{
			"create",
			"address_set",
			"name=" + as.hashName,
			"external-ids:name=" + as.name,
		}
		joinedIPs := joinIPs(as.allIPs())
		if len(joinedIPs) > 0 {
			args = append(args, "addresses="+joinedIPs)
		}
		as.uuid, stderr, err = util.RunOVNNbctl(args...)
		if err != nil {
			return nil, fmt.Errorf("failed to create address set %q, stderr: %q (%v)",
				asDetail(as), stderr, err)
		}
	}

	klog.V(5).Infof("New(%s) with %v", asDetail(as), ips)

	return as, nil
}

func (as *ovnAddressSets) GetASHashNames() (string, string) {
	var ipv4AS string
	var ipv6AS string
	if as.ipv4 != nil {
		ipv4AS = as.ipv4.hashName
	}
	if as.ipv6 != nil {
		ipv6AS = as.ipv6.hashName
	}
	return ipv4AS, ipv6AS
}

func (as *ovnAddressSets) GetName() string {
	return as.name
}

func (as *ovnAddressSets) SetIPs(ips []net.IP) error {
	var err error
	as.Lock()
	defer as.Unlock()

	v4ips, v6ips := splitIPsByFamily(ips)

	if as.ipv6 != nil {
		err = as.ipv6.setIPs(v6ips)
	}
	if as.ipv4 != nil {
		err = errors.Wrapf(err, "%v", as.ipv4.setIPs(v4ips))
	}

	return err
}

func (as *ovnAddressSets) AddIPs(ips []net.IP) (time.Duration, time.Duration, error) {
	if len(ips) == 0 {
		return 0 * time.Second, 0 * time.Second, nil
	}

	start := time.Now()
	as.Lock()
	defer as.Unlock()
	lockEnd := time.Since(start)

	start = time.Now()
	v4ips, v6ips := splitIPsByFamily(ips)
	if as.ipv6 != nil {
		if err := as.ipv6.addIPs(v6ips); err != nil {
			return 0 * time.Second, 0 * time.Second, fmt.Errorf("failed to AddIPs to the v6 set: %w", err)
		}
	}
	if as.ipv4 != nil {
		if err := as.ipv4.addIPs(v4ips); err != nil {
			return 0 * time.Second, 0 * time.Second, fmt.Errorf("failed to AddIPs to the v4 set: %w", err)
		}
	}
	addEnd := time.Since(start)

	return lockEnd, addEnd, nil
}

func (as *ovnAddressSets) DeleteIPs(ips []net.IP) error {
	if len(ips) == 0 {
		return nil
	}

	as.Lock()
	defer as.Unlock()

	v4ips, v6ips := splitIPsByFamily(ips)
	if as.ipv6 != nil {
		if err := as.ipv6.deleteIPs(v6ips); err != nil {
			return fmt.Errorf("failed to DeleteIPs to the v6 set: %w", err)
		}
	}
	if as.ipv4 != nil {
		if err := as.ipv4.deleteIPs(v4ips); err != nil {
			return fmt.Errorf("failed to DeleteIPs to the v4 set: %w", err)
		}
	}
	return nil
}

func (as *ovnAddressSets) Destroy() error {
	as.Lock()
	defer as.Unlock()

	if as.ipv4 != nil {
		err := as.ipv4.destroy()
		if err != nil {
			return err
		}
		as.ipv4 = nil
	}
	if as.ipv6 != nil {
		err := as.ipv6.destroy()
		if err != nil {
			return err
		}
		as.ipv6 = nil
	}
	return nil
}

// setIP updates the given address set in OVN to be only the given IPs, disregarding
// existing state.
func (as *ovnAddressSet) setIPs(ips []net.IP) error {
klog.Errorf("### setting Ips to %v", ips)
	if len(ips) > 0 {
		as.ops <- &addrOp{
			op:  addrOpSet,
			ips: ips,
		}
	} else {
		as.ops <- &addrOp{
			op:  addrOpClear,
		}
	}
	return nil
}

// addIPs appends the set of IPs to the existing address_set.
func (as *ovnAddressSet) addIPs(ips []net.IP) error {
	as.ops <- &addrOp{
		op:  addrOpAdd,
		ips: ips,
	}
	return nil
}

// deleteIPs removes selected IPs from the existing address_set
func (as *ovnAddressSet) deleteIPs(ips []net.IP) error {
	as.ops <- &addrOp{
		op:  addrOpDel,
		ips: ips,
	}
	return nil
}

func (as *ovnAddressSet) destroy() error {
	close(as.stopCh)
	as.doneWg.Wait()

	klog.V(5).Infof("destroy(%s)", asDetail(as))
	_, stderr, err := util.RunOVNNbctl("--if-exists", "destroy", "address_set", as.uuid)
	if err != nil {
		return fmt.Errorf("failed to destroy address set %q, stderr: %q, (%v)",
			asDetail(as), stderr, err)
	}
	as.ips = nil
	return nil
}

func MakeAddressSetName(name string) (string, string) {
	return name + ipv4AddressSetSuffix, name + ipv6AddressSetSuffix
}

func MakeAddressSetHashNames(name string) (string, string) {
	ipv4AddressSetName, ipv6AddressSetName := MakeAddressSetName(name)
	return hashedAddressSet(ipv4AddressSetName), hashedAddressSet(ipv6AddressSetName)
}

// splitIPsByFamily takes a slice of IPs and returns two slices, with
// v4 and v6 addresses collated accordingly.
func splitIPsByFamily(ips []net.IP) (v4 []net.IP, v6 []net.IP) {
	for _, ip := range ips {
		if utilnet.IsIPv6(ip) {
			v6 = append(v6, ip)
		} else {
			v4 = append(v4, ip)
		}
	}
	return
}

func joinIPs(ips []net.IP) string {
	list := make([]string, 0, len(ips))
	for _, ip := range ips {
		list = append(list, `"`+ip.String()+`"`)
	}
	// so tests are predictable
	sort.Strings(list)
	return strings.Join(list, " ")
}

func (as *ovnAddressSet) allIPs() []net.IP {
	// my kingdom for a ".values()" function
	out := make([]net.IP, 0, len(as.ips))
	for _, ip := range as.ips {
		out = append(out, ip)
	}
	return out
}
