// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package vswitchdb

// Queue defines an object in Queue table
type Queue struct {
	UUID        string            `ovsdb:"_uuid"`
	DSCP        *int              `ovsdb:"dscp"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	OtherConfig map[string]string `ovsdb:"other_config"`
}
