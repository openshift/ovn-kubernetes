// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package vswitchdb

// AutoAttach defines an object in AutoAttach table
type AutoAttach struct {
	UUID              string      `ovsdb:"_uuid"`
	Mappings          map[int]int `ovsdb:"mappings"`
	SystemDescription string      `ovsdb:"system_description"`
	SystemName        string      `ovsdb:"system_name"`
}
