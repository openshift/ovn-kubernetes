// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package nbdb

import "github.com/ovn-kubernetes/libovsdb/model"

const SampleTable = "Sample"

// Sample defines an object in Sample table
type Sample struct {
	UUID       string   `ovsdb:"_uuid"`
	Collectors []string `ovsdb:"collectors"`
	Metadata   int      `ovsdb:"metadata"`
}

func (a *Sample) GetUUID() string {
	return a.UUID
}

func (a *Sample) GetCollectors() []string {
	return a.Collectors
}

func copySampleCollectors(a []string) []string {
	if a == nil {
		return nil
	}
	b := make([]string, len(a))
	copy(b, a)
	return b
}

func equalSampleCollectors(a, b []string) bool {
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

func (a *Sample) GetMetadata() int {
	return a.Metadata
}

func (a *Sample) DeepCopyInto(b *Sample) {
	*b = *a
	b.Collectors = copySampleCollectors(a.Collectors)
}

func (a *Sample) DeepCopy() *Sample {
	b := new(Sample)
	a.DeepCopyInto(b)
	return b
}

func (a *Sample) CloneModelInto(b model.Model) {
	c := b.(*Sample)
	a.DeepCopyInto(c)
}

func (a *Sample) CloneModel() model.Model {
	return a.DeepCopy()
}

func (a *Sample) Equals(b *Sample) bool {
	return a.UUID == b.UUID &&
		equalSampleCollectors(a.Collectors, b.Collectors) &&
		a.Metadata == b.Metadata
}

func (a *Sample) EqualsModel(b model.Model) bool {
	c := b.(*Sample)
	return a.Equals(c)
}

var _ model.CloneableModel = &Sample{}
var _ model.ComparableModel = &Sample{}
