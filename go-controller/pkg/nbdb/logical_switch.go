// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package nbdb

import "github.com/ovn-kubernetes/libovsdb/model"

const LogicalSwitchTable = "Logical_Switch"

// LogicalSwitch defines an object in Logical_Switch table
type LogicalSwitch struct {
	UUID              string            `ovsdb:"_uuid"`
	ACLs              []string          `ovsdb:"acls"`
	Copp              *string           `ovsdb:"copp"`
	DNSRecords        []string          `ovsdb:"dns_records"`
	ExternalIDs       map[string]string `ovsdb:"external_ids"`
	ForwardingGroups  []string          `ovsdb:"forwarding_groups"`
	LoadBalancer      []string          `ovsdb:"load_balancer"`
	LoadBalancerGroup []string          `ovsdb:"load_balancer_group"`
	Name              string            `ovsdb:"name"`
	OtherConfig       map[string]string `ovsdb:"other_config"`
	Ports             []string          `ovsdb:"ports"`
	QOSRules          []string          `ovsdb:"qos_rules"`
}

func (a *LogicalSwitch) GetUUID() string {
	return a.UUID
}

func (a *LogicalSwitch) GetACLs() []string {
	return a.ACLs
}

func copyLogicalSwitchACLs(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalLogicalSwitchACLs(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func (a *LogicalSwitch) GetCopp() *string {
	return a.Copp
}

func copyLogicalSwitchCopp(a *string) *string {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalLogicalSwitchCopp(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *LogicalSwitch) GetDNSRecords() []string {
	return a.DNSRecords
}

func copyLogicalSwitchDNSRecords(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalLogicalSwitchDNSRecords(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func (a *LogicalSwitch) GetExternalIDs() map[string]string {
	return a.ExternalIDs
}

func copyLogicalSwitchExternalIDs(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalLogicalSwitchExternalIDs(a, b map[string]string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func (a *LogicalSwitch) GetForwardingGroups() []string {
	return a.ForwardingGroups
}

func copyLogicalSwitchForwardingGroups(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalLogicalSwitchForwardingGroups(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func (a *LogicalSwitch) GetLoadBalancer() []string {
	return a.LoadBalancer
}

func copyLogicalSwitchLoadBalancer(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalLogicalSwitchLoadBalancer(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func (a *LogicalSwitch) GetLoadBalancerGroup() []string {
	return a.LoadBalancerGroup
}

func copyLogicalSwitchLoadBalancerGroup(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalLogicalSwitchLoadBalancerGroup(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func (a *LogicalSwitch) GetName() string {
	return a.Name
}

func (a *LogicalSwitch) GetOtherConfig() map[string]string {
	return a.OtherConfig
}

func copyLogicalSwitchOtherConfig(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalLogicalSwitchOtherConfig(a, b map[string]string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if w, ok := b[k]; !ok || v != w {
			return false
		}
	}
	return true
}

func (a *LogicalSwitch) GetPorts() []string {
	return a.Ports
}

func copyLogicalSwitchPorts(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalLogicalSwitchPorts(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func (a *LogicalSwitch) GetQOSRules() []string {
	return a.QOSRules
}

func copyLogicalSwitchQOSRules(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalLogicalSwitchQOSRules(a, b []string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

func (a *LogicalSwitch) DeepCopyInto(b *LogicalSwitch) {
	*b = *a
	b.ACLs = copyLogicalSwitchACLs(a.ACLs)
	b.Copp = copyLogicalSwitchCopp(a.Copp)
	b.DNSRecords = copyLogicalSwitchDNSRecords(a.DNSRecords)
	b.ExternalIDs = copyLogicalSwitchExternalIDs(a.ExternalIDs)
	b.ForwardingGroups = copyLogicalSwitchForwardingGroups(a.ForwardingGroups)
	b.LoadBalancer = copyLogicalSwitchLoadBalancer(a.LoadBalancer)
	b.LoadBalancerGroup = copyLogicalSwitchLoadBalancerGroup(a.LoadBalancerGroup)
	b.OtherConfig = copyLogicalSwitchOtherConfig(a.OtherConfig)
	b.Ports = copyLogicalSwitchPorts(a.Ports)
	b.QOSRules = copyLogicalSwitchQOSRules(a.QOSRules)
}

func (a *LogicalSwitch) DeepCopy() *LogicalSwitch {
	b := new(LogicalSwitch)
	a.DeepCopyInto(b)
	return b
}

func (a *LogicalSwitch) CloneModelInto(b model.Model) {
	c := b.(*LogicalSwitch)
	a.DeepCopyInto(c)
}

func (a *LogicalSwitch) CloneModel() model.Model {
	return a.DeepCopy()
}

func (a *LogicalSwitch) Equals(b *LogicalSwitch) bool {
	return a.UUID == b.UUID &&
		equalLogicalSwitchACLs(a.ACLs, b.ACLs) &&
		equalLogicalSwitchCopp(a.Copp, b.Copp) &&
		equalLogicalSwitchDNSRecords(a.DNSRecords, b.DNSRecords) &&
		equalLogicalSwitchExternalIDs(a.ExternalIDs, b.ExternalIDs) &&
		equalLogicalSwitchForwardingGroups(a.ForwardingGroups, b.ForwardingGroups) &&
		equalLogicalSwitchLoadBalancer(a.LoadBalancer, b.LoadBalancer) &&
		equalLogicalSwitchLoadBalancerGroup(a.LoadBalancerGroup, b.LoadBalancerGroup) &&
		a.Name == b.Name &&
		equalLogicalSwitchOtherConfig(a.OtherConfig, b.OtherConfig) &&
		equalLogicalSwitchPorts(a.Ports, b.Ports) &&
		equalLogicalSwitchQOSRules(a.QOSRules, b.QOSRules)
}

func (a *LogicalSwitch) EqualsModel(b model.Model) bool {
	c := b.(*LogicalSwitch)
	return a.Equals(c)
}

var _ model.CloneableModel = &LogicalSwitch{}
var _ model.ComparableModel = &LogicalSwitch{}
