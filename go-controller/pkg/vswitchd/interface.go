// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package vswitchd

import "github.com/ovn-org/libovsdb/model"

const InterfaceTable = "Interface"

type (
	InterfaceAdminState       = string
	InterfaceCFMRemoteOpstate = string
	InterfaceDuplex           = string
	InterfaceLinkState        = string
)

var (
	InterfaceAdminStateUp         InterfaceAdminState       = "up"
	InterfaceAdminStateDown       InterfaceAdminState       = "down"
	InterfaceCFMRemoteOpstateUp   InterfaceCFMRemoteOpstate = "up"
	InterfaceCFMRemoteOpstateDown InterfaceCFMRemoteOpstate = "down"
	InterfaceDuplexHalf           InterfaceDuplex           = "half"
	InterfaceDuplexFull           InterfaceDuplex           = "full"
	InterfaceLinkStateUp          InterfaceLinkState        = "up"
	InterfaceLinkStateDown        InterfaceLinkState        = "down"
)

// Interface defines an object in Interface table
type Interface struct {
	UUID                      string                     `ovsdb:"_uuid"`
	AdminState                *InterfaceAdminState       `ovsdb:"admin_state"`
	BFD                       map[string]string          `ovsdb:"bfd"`
	BFDStatus                 map[string]string          `ovsdb:"bfd_status"`
	CFMFault                  *bool                      `ovsdb:"cfm_fault"`
	CFMFaultStatus            []string                   `ovsdb:"cfm_fault_status"`
	CFMFlapCount              *int                       `ovsdb:"cfm_flap_count"`
	CFMHealth                 *int                       `ovsdb:"cfm_health"`
	CFMMpid                   *int                       `ovsdb:"cfm_mpid"`
	CFMRemoteMpids            []int                      `ovsdb:"cfm_remote_mpids"`
	CFMRemoteOpstate          *InterfaceCFMRemoteOpstate `ovsdb:"cfm_remote_opstate"`
	Duplex                    *InterfaceDuplex           `ovsdb:"duplex"`
	Error                     *string                    `ovsdb:"error"`
	ExternalIDs               map[string]string          `ovsdb:"external_ids"`
	Ifindex                   *int                       `ovsdb:"ifindex"`
	IngressPolicingBurst      int                        `ovsdb:"ingress_policing_burst"`
	IngressPolicingKpktsBurst int                        `ovsdb:"ingress_policing_kpkts_burst"`
	IngressPolicingKpktsRate  int                        `ovsdb:"ingress_policing_kpkts_rate"`
	IngressPolicingRate       int                        `ovsdb:"ingress_policing_rate"`
	LACPCurrent               *bool                      `ovsdb:"lacp_current"`
	LinkResets                *int                       `ovsdb:"link_resets"`
	LinkSpeed                 *int                       `ovsdb:"link_speed"`
	LinkState                 *InterfaceLinkState        `ovsdb:"link_state"`
	LLDP                      map[string]string          `ovsdb:"lldp"`
	MAC                       *string                    `ovsdb:"mac"`
	MACInUse                  *string                    `ovsdb:"mac_in_use"`
	MTU                       *int                       `ovsdb:"mtu"`
	MTURequest                *int                       `ovsdb:"mtu_request"`
	Name                      string                     `ovsdb:"name"`
	Ofport                    *int                       `ovsdb:"ofport"`
	OfportRequest             *int                       `ovsdb:"ofport_request"`
	Options                   map[string]string          `ovsdb:"options"`
	OtherConfig               map[string]string          `ovsdb:"other_config"`
	Statistics                map[string]int             `ovsdb:"statistics"`
	Status                    map[string]string          `ovsdb:"status"`
	Type                      string                     `ovsdb:"type"`
}

func (a *Interface) GetUUID() string {
	return a.UUID
}

func (a *Interface) GetAdminState() *InterfaceAdminState {
	return a.AdminState
}

func copyInterfaceAdminState(a *InterfaceAdminState) *InterfaceAdminState {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceAdminState(a, b *InterfaceAdminState) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetBFD() map[string]string {
	return a.BFD
}

func copyInterfaceBFD(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalInterfaceBFD(a, b map[string]string) bool {
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

func (a *Interface) GetBFDStatus() map[string]string {
	return a.BFDStatus
}

func copyInterfaceBFDStatus(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalInterfaceBFDStatus(a, b map[string]string) bool {
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

func (a *Interface) GetCFMFault() *bool {
	return a.CFMFault
}

func copyInterfaceCFMFault(a *bool) *bool {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceCFMFault(a, b *bool) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetCFMFaultStatus() []string {
	return a.CFMFaultStatus
}

func copyInterfaceCFMFaultStatus(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalInterfaceCFMFaultStatus(a, b []string) bool {
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

func (a *Interface) GetCFMFlapCount() *int {
	return a.CFMFlapCount
}

func copyInterfaceCFMFlapCount(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceCFMFlapCount(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetCFMHealth() *int {
	return a.CFMHealth
}

func copyInterfaceCFMHealth(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceCFMHealth(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetCFMMpid() *int {
	return a.CFMMpid
}

func copyInterfaceCFMMpid(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceCFMMpid(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetCFMRemoteMpids() []int {
	return a.CFMRemoteMpids
}

func copyInterfaceCFMRemoteMpids(a []int) []int {
	if a == nil {
		return nil
	}
	b := make([]int, len(a))
	copy(b, a)
	return b
}

func equalInterfaceCFMRemoteMpids(a, b []int) bool {
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

func (a *Interface) GetCFMRemoteOpstate() *InterfaceCFMRemoteOpstate {
	return a.CFMRemoteOpstate
}

func copyInterfaceCFMRemoteOpstate(a *InterfaceCFMRemoteOpstate) *InterfaceCFMRemoteOpstate {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceCFMRemoteOpstate(a, b *InterfaceCFMRemoteOpstate) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetDuplex() *InterfaceDuplex {
	return a.Duplex
}

func copyInterfaceDuplex(a *InterfaceDuplex) *InterfaceDuplex {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceDuplex(a, b *InterfaceDuplex) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetError() *string {
	return a.Error
}

func copyInterfaceError(a *string) *string {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceError(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetExternalIDs() map[string]string {
	return a.ExternalIDs
}

func copyInterfaceExternalIDs(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalInterfaceExternalIDs(a, b map[string]string) bool {
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

func (a *Interface) GetIfindex() *int {
	return a.Ifindex
}

func copyInterfaceIfindex(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceIfindex(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetIngressPolicingBurst() int {
	return a.IngressPolicingBurst
}

func (a *Interface) GetIngressPolicingKpktsBurst() int {
	return a.IngressPolicingKpktsBurst
}

func (a *Interface) GetIngressPolicingKpktsRate() int {
	return a.IngressPolicingKpktsRate
}

func (a *Interface) GetIngressPolicingRate() int {
	return a.IngressPolicingRate
}

func (a *Interface) GetLACPCurrent() *bool {
	return a.LACPCurrent
}

func copyInterfaceLACPCurrent(a *bool) *bool {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceLACPCurrent(a, b *bool) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetLinkResets() *int {
	return a.LinkResets
}

func copyInterfaceLinkResets(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceLinkResets(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetLinkSpeed() *int {
	return a.LinkSpeed
}

func copyInterfaceLinkSpeed(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceLinkSpeed(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetLinkState() *InterfaceLinkState {
	return a.LinkState
}

func copyInterfaceLinkState(a *InterfaceLinkState) *InterfaceLinkState {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceLinkState(a, b *InterfaceLinkState) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetLLDP() map[string]string {
	return a.LLDP
}

func copyInterfaceLLDP(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalInterfaceLLDP(a, b map[string]string) bool {
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

func (a *Interface) GetMAC() *string {
	return a.MAC
}

func copyInterfaceMAC(a *string) *string {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceMAC(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetMACInUse() *string {
	return a.MACInUse
}

func copyInterfaceMACInUse(a *string) *string {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceMACInUse(a, b *string) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetMTU() *int {
	return a.MTU
}

func copyInterfaceMTU(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceMTU(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetMTURequest() *int {
	return a.MTURequest
}

func copyInterfaceMTURequest(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceMTURequest(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetName() string {
	return a.Name
}

func (a *Interface) GetOfport() *int {
	return a.Ofport
}

func copyInterfaceOfport(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceOfport(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetOfportRequest() *int {
	return a.OfportRequest
}

func copyInterfaceOfportRequest(a *int) *int {
	if a == nil {
		return nil
	}
	b := *a
	return &b
}

func equalInterfaceOfportRequest(a, b *int) bool {
	if (a == nil) != (b == nil) {
		return false
	}
	if a == b {
		return true
	}
	return *a == *b
}

func (a *Interface) GetOptions() map[string]string {
	return a.Options
}

func copyInterfaceOptions(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalInterfaceOptions(a, b map[string]string) bool {
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

func (a *Interface) GetOtherConfig() map[string]string {
	return a.OtherConfig
}

func copyInterfaceOtherConfig(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalInterfaceOtherConfig(a, b map[string]string) bool {
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

func (a *Interface) GetStatistics() map[string]int {
	return a.Statistics
}

func copyInterfaceStatistics(a map[string]int) map[string]int {
	if a == nil {
		return nil
	}
	b := make(map[string]int, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalInterfaceStatistics(a, b map[string]int) bool {
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

func (a *Interface) GetStatus() map[string]string {
	return a.Status
}

func copyInterfaceStatus(a map[string]string) map[string]string {
	if a == nil {
		return nil
	}
	b := make(map[string]string, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalInterfaceStatus(a, b map[string]string) bool {
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

func (a *Interface) GetType() string {
	return a.Type
}

func (a *Interface) DeepCopyInto(b *Interface) {
	*b = *a
	b.AdminState = copyInterfaceAdminState(a.AdminState)
	b.BFD = copyInterfaceBFD(a.BFD)
	b.BFDStatus = copyInterfaceBFDStatus(a.BFDStatus)
	b.CFMFault = copyInterfaceCFMFault(a.CFMFault)
	b.CFMFaultStatus = copyInterfaceCFMFaultStatus(a.CFMFaultStatus)
	b.CFMFlapCount = copyInterfaceCFMFlapCount(a.CFMFlapCount)
	b.CFMHealth = copyInterfaceCFMHealth(a.CFMHealth)
	b.CFMMpid = copyInterfaceCFMMpid(a.CFMMpid)
	b.CFMRemoteMpids = copyInterfaceCFMRemoteMpids(a.CFMRemoteMpids)
	b.CFMRemoteOpstate = copyInterfaceCFMRemoteOpstate(a.CFMRemoteOpstate)
	b.Duplex = copyInterfaceDuplex(a.Duplex)
	b.Error = copyInterfaceError(a.Error)
	b.ExternalIDs = copyInterfaceExternalIDs(a.ExternalIDs)
	b.Ifindex = copyInterfaceIfindex(a.Ifindex)
	b.LACPCurrent = copyInterfaceLACPCurrent(a.LACPCurrent)
	b.LinkResets = copyInterfaceLinkResets(a.LinkResets)
	b.LinkSpeed = copyInterfaceLinkSpeed(a.LinkSpeed)
	b.LinkState = copyInterfaceLinkState(a.LinkState)
	b.LLDP = copyInterfaceLLDP(a.LLDP)
	b.MAC = copyInterfaceMAC(a.MAC)
	b.MACInUse = copyInterfaceMACInUse(a.MACInUse)
	b.MTU = copyInterfaceMTU(a.MTU)
	b.MTURequest = copyInterfaceMTURequest(a.MTURequest)
	b.Ofport = copyInterfaceOfport(a.Ofport)
	b.OfportRequest = copyInterfaceOfportRequest(a.OfportRequest)
	b.Options = copyInterfaceOptions(a.Options)
	b.OtherConfig = copyInterfaceOtherConfig(a.OtherConfig)
	b.Statistics = copyInterfaceStatistics(a.Statistics)
	b.Status = copyInterfaceStatus(a.Status)
}

func (a *Interface) DeepCopy() *Interface {
	b := new(Interface)
	a.DeepCopyInto(b)
	return b
}

func (a *Interface) CloneModelInto(b model.Model) {
	c := b.(*Interface)
	a.DeepCopyInto(c)
}

func (a *Interface) CloneModel() model.Model {
	return a.DeepCopy()
}

func (a *Interface) Equals(b *Interface) bool {
	return a.UUID == b.UUID &&
		equalInterfaceAdminState(a.AdminState, b.AdminState) &&
		equalInterfaceBFD(a.BFD, b.BFD) &&
		equalInterfaceBFDStatus(a.BFDStatus, b.BFDStatus) &&
		equalInterfaceCFMFault(a.CFMFault, b.CFMFault) &&
		equalInterfaceCFMFaultStatus(a.CFMFaultStatus, b.CFMFaultStatus) &&
		equalInterfaceCFMFlapCount(a.CFMFlapCount, b.CFMFlapCount) &&
		equalInterfaceCFMHealth(a.CFMHealth, b.CFMHealth) &&
		equalInterfaceCFMMpid(a.CFMMpid, b.CFMMpid) &&
		equalInterfaceCFMRemoteMpids(a.CFMRemoteMpids, b.CFMRemoteMpids) &&
		equalInterfaceCFMRemoteOpstate(a.CFMRemoteOpstate, b.CFMRemoteOpstate) &&
		equalInterfaceDuplex(a.Duplex, b.Duplex) &&
		equalInterfaceError(a.Error, b.Error) &&
		equalInterfaceExternalIDs(a.ExternalIDs, b.ExternalIDs) &&
		equalInterfaceIfindex(a.Ifindex, b.Ifindex) &&
		a.IngressPolicingBurst == b.IngressPolicingBurst &&
		a.IngressPolicingKpktsBurst == b.IngressPolicingKpktsBurst &&
		a.IngressPolicingKpktsRate == b.IngressPolicingKpktsRate &&
		a.IngressPolicingRate == b.IngressPolicingRate &&
		equalInterfaceLACPCurrent(a.LACPCurrent, b.LACPCurrent) &&
		equalInterfaceLinkResets(a.LinkResets, b.LinkResets) &&
		equalInterfaceLinkSpeed(a.LinkSpeed, b.LinkSpeed) &&
		equalInterfaceLinkState(a.LinkState, b.LinkState) &&
		equalInterfaceLLDP(a.LLDP, b.LLDP) &&
		equalInterfaceMAC(a.MAC, b.MAC) &&
		equalInterfaceMACInUse(a.MACInUse, b.MACInUse) &&
		equalInterfaceMTU(a.MTU, b.MTU) &&
		equalInterfaceMTURequest(a.MTURequest, b.MTURequest) &&
		a.Name == b.Name &&
		equalInterfaceOfport(a.Ofport, b.Ofport) &&
		equalInterfaceOfportRequest(a.OfportRequest, b.OfportRequest) &&
		equalInterfaceOptions(a.Options, b.Options) &&
		equalInterfaceOtherConfig(a.OtherConfig, b.OtherConfig) &&
		equalInterfaceStatistics(a.Statistics, b.Statistics) &&
		equalInterfaceStatus(a.Status, b.Status) &&
		a.Type == b.Type
}

func (a *Interface) EqualsModel(b model.Model) bool {
	c := b.(*Interface)
	return a.Equals(c)
}

var _ model.CloneableModel = &Interface{}
var _ model.ComparableModel = &Interface{}
