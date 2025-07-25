// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package vswitchd

import "github.com/ovn-kubernetes/libovsdb/model"

const AutoAttachTable = "AutoAttach"

// AutoAttach defines an object in AutoAttach table
type AutoAttach struct {
	UUID              string      `ovsdb:"_uuid"`
	Mappings          map[int]int `ovsdb:"mappings"`
	SystemDescription string      `ovsdb:"system_description"`
	SystemName        string      `ovsdb:"system_name"`
}

func (a *AutoAttach) GetUUID() string {
	return a.UUID
}

func (a *AutoAttach) GetMappings() map[int]int {
	return a.Mappings
}

func copyAutoAttachMappings(a map[int]int) map[int]int {
	if a == nil {
		return nil
	}
	b := make(map[int]int, len(a))
	for k, v := range a {
		b[k] = v
	}
	return b
}

func equalAutoAttachMappings(a, b map[int]int) bool {
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

func (a *AutoAttach) GetSystemDescription() string {
	return a.SystemDescription
}

func (a *AutoAttach) GetSystemName() string {
	return a.SystemName
}

func (a *AutoAttach) DeepCopyInto(b *AutoAttach) {
	*b = *a
	b.Mappings = copyAutoAttachMappings(a.Mappings)
}

func (a *AutoAttach) DeepCopy() *AutoAttach {
	b := new(AutoAttach)
	a.DeepCopyInto(b)
	return b
}

func (a *AutoAttach) CloneModelInto(b model.Model) {
	c := b.(*AutoAttach)
	a.DeepCopyInto(c)
}

func (a *AutoAttach) CloneModel() model.Model {
	return a.DeepCopy()
}

func (a *AutoAttach) Equals(b *AutoAttach) bool {
	return a.UUID == b.UUID &&
		equalAutoAttachMappings(a.Mappings, b.Mappings) &&
		a.SystemDescription == b.SystemDescription &&
		a.SystemName == b.SystemName
}

func (a *AutoAttach) EqualsModel(b model.Model) bool {
	c := b.(*AutoAttach)
	return a.Equals(c)
}

var _ model.CloneableModel = &AutoAttach{}
var _ model.ComparableModel = &AutoAttach{}
