// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package sbdb

// GatewayChassis defines an object in Gateway_Chassis table
type GatewayChassis struct {
	UUID        string            `ovsdb:"_uuid"`
	Chassis     *string           `ovsdb:"chassis"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	Name        string            `ovsdb:"name"`
	Options     map[string]string `ovsdb:"options"`
	Priority    int               `ovsdb:"priority"`
}
