// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package vswitchdb

// FlowSampleCollectorSet defines an object in Flow_Sample_Collector_Set table
type FlowSampleCollectorSet struct {
	UUID        string            `ovsdb:"_uuid"`
	Bridge      string            `ovsdb:"bridge"`
	ExternalIDs map[string]string `ovsdb:"external_ids"`
	ID          int               `ovsdb:"id"`
	IPFIX       *string           `ovsdb:"ipfix"`
}
