// Code generated by "libovsdb.modelgen"
// DO NOT EDIT.

package serverdb

type (
	DatabaseModel = string
)

var (
	DatabaseModelStandalone DatabaseModel = "standalone"
	DatabaseModelClustered  DatabaseModel = "clustered"
	DatabaseModelRelay      DatabaseModel = "relay"
)

// Database defines an object in Database table
type Database struct {
	UUID      string        `ovsdb:"_uuid"`
	Cid       *string       `ovsdb:"cid"`
	Connected bool          `ovsdb:"connected"`
	Index     *int          `ovsdb:"index"`
	Leader    bool          `ovsdb:"leader"`
	Model     DatabaseModel `ovsdb:"model"`
	Name      string        `ovsdb:"name"`
	Schema    *string       `ovsdb:"schema"`
	Sid       *string       `ovsdb:"sid"`
}
