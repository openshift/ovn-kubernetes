package libovsdbops

import (
	"fmt"
	"reflect"

	"github.com/ovn-org/libovsdb/model"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/nbdb"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/sbdb"
)

func getUUID(model model.Model) string {
	switch t := model.(type) {
	case *nbdb.ACL:
		return t.UUID
	case *nbdb.AddressSet:
		return t.UUID
	case *nbdb.BFD:
		return t.UUID
	case *nbdb.GatewayChassis:
		return t.UUID
	case *nbdb.LoadBalancer:
		return t.UUID
	case *nbdb.LogicalRouter:
		return t.UUID
	case *nbdb.LogicalRouterPolicy:
		return t.UUID
	case *nbdb.LogicalRouterPort:
		return t.UUID
	case *nbdb.LogicalRouterStaticRoute:
		return t.UUID
	case *nbdb.LogicalSwitch:
		return t.UUID
	case *nbdb.LogicalSwitchPort:
		return t.UUID
	case *nbdb.NAT:
		return t.UUID
	case *nbdb.PortGroup:
		return t.UUID
	case *sbdb.Chassis:
		return t.UUID
	case *sbdb.MACBinding:
		return t.UUID
	default:
		panic(fmt.Sprintf("getUUID: unknown model %T", t))
	}
}

func setUUID(model model.Model, uuid string) {
	switch t := model.(type) {
	case *nbdb.ACL:
		t.UUID = uuid
	case *nbdb.AddressSet:
		t.UUID = uuid
	case *nbdb.BFD:
		t.UUID = uuid
	case *nbdb.GatewayChassis:
		t.UUID = uuid
	case *nbdb.LoadBalancer:
		t.UUID = uuid
	case *nbdb.LogicalRouter:
		t.UUID = uuid
	case *nbdb.LogicalRouterPolicy:
		t.UUID = uuid
	case *nbdb.LogicalRouterPort:
		t.UUID = uuid
	case *nbdb.LogicalRouterStaticRoute:
		t.UUID = uuid
	case *nbdb.LogicalSwitch:
		t.UUID = uuid
	case *nbdb.LogicalSwitchPort:
		t.UUID = uuid
	case *nbdb.NAT:
		t.UUID = uuid
	case *nbdb.PortGroup:
		t.UUID = uuid
	case *sbdb.Chassis:
		t.UUID = uuid
	case *sbdb.MACBinding:
		t.UUID = uuid
	default:
		panic(fmt.Sprintf("setUUID: unknown model %T", t))
	}
}

func copyIndexes(model model.Model) model.Model {
	switch t := model.(type) {
	case *nbdb.ACL:
		return &nbdb.ACL{
			UUID: t.UUID,
		}
	case *nbdb.AddressSet:
		return &nbdb.AddressSet{
			UUID: t.UUID,
			Name: t.Name,
		}
	case *nbdb.BFD:
		return &nbdb.BFD{
			UUID:        t.UUID,
			LogicalPort: t.LogicalPort,
			DstIP:       t.DstIP,
		}
	case *nbdb.GatewayChassis:
		return &nbdb.GatewayChassis{
			UUID: t.UUID,
			Name: t.Name,
		}
	case *nbdb.LoadBalancer:
		return &nbdb.LoadBalancer{
			UUID: t.UUID,
		}
	case *nbdb.LogicalRouter:
		return &nbdb.LogicalRouter{
			UUID: t.UUID,
		}
	case *nbdb.LogicalRouterPolicy:
		return &nbdb.LogicalRouterPolicy{
			UUID: t.UUID,
		}
	case *nbdb.LogicalRouterPort:
		return &nbdb.LogicalRouterPort{
			UUID: t.UUID,
			Name: t.Name,
		}
	case *nbdb.LogicalRouterStaticRoute:
		return &nbdb.LogicalRouterStaticRoute{
			UUID: t.UUID,
		}
	case *nbdb.LogicalSwitch:
		return &nbdb.LogicalSwitch{
			UUID: t.UUID,
		}
	case *nbdb.LogicalSwitchPort:
		return &nbdb.LogicalSwitchPort{
			UUID: t.UUID,
			Name: t.Name,
		}
	case *nbdb.NAT:
		return &nbdb.NAT{
			UUID: t.UUID,
		}
	case *nbdb.PortGroup:
		return &nbdb.PortGroup{
			UUID: t.UUID,
			Name: t.Name,
		}
	case *sbdb.Chassis:
		return &sbdb.Chassis{
			UUID: t.UUID,
			Name: t.Name,
		}
	case *sbdb.MACBinding:
		return &sbdb.MACBinding{
			UUID: t.UUID,
			IP:   t.IP,
		}
	default:
		panic(fmt.Sprintf("copyIndexes: unknown model %T", t))
	}
}

func getListFromModel(model model.Model) interface{} {
	switch t := model.(type) {
	case *nbdb.ACL:
		return &[]nbdb.ACL{}
	case *nbdb.AddressSet:
		return &[]nbdb.AddressSet{}
	case *nbdb.BFD:
		return &[]nbdb.BFD{}
	case *nbdb.GatewayChassis:
		return &[]nbdb.GatewayChassis{}
	case *nbdb.LoadBalancer:
		return &[]nbdb.LoadBalancer{}
	case *nbdb.LogicalRouter:
		return &[]nbdb.LogicalRouter{}
	case *nbdb.LogicalRouterPolicy:
		return &[]nbdb.LogicalRouterPolicy{}
	case *nbdb.LogicalRouterPort:
		return &[]nbdb.LogicalRouterPort{}
	case *nbdb.LogicalRouterStaticRoute:
		return &[]nbdb.LogicalRouterStaticRoute{}
	case *nbdb.LogicalSwitch:
		return &[]nbdb.LogicalSwitch{}
	case *nbdb.LogicalSwitchPort:
		return &[]nbdb.LogicalSwitchPort{}
	case *nbdb.NAT:
		return &[]nbdb.NAT{}
	case *nbdb.PortGroup:
		return &[]nbdb.PortGroup{}
	case *sbdb.Chassis:
		return &[]sbdb.Chassis{}
	case *sbdb.MACBinding:
		return &[]sbdb.MACBinding{}
	default:
		panic(fmt.Sprintf("getModelList: unknown model %T", t))
	}
}

// onModels applies the provided function to a collection of
// models presented in different ways:
// - a single model (pointer to a struct)
// - a slice of models or pointer to slice of models
// - a slice of structs or pointer to a slice of structs
// If the provided function returns an error, iteration stops and
// that error is returned.
func onModels(models interface{}, do func(interface{}) error) error {
	v := reflect.ValueOf(models)
	if !v.IsValid() {
		return nil
	}
	if v.Kind() == reflect.Ptr {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	switch v.Kind() {
	case reflect.Slice:
		switch v.Type().Elem().Kind() {
		case reflect.Struct:
			for i := 0; i < v.Len(); i++ {
				model := v.Index(i).Addr().Interface()
				err := do(model)
				if err != nil {
					return err
				}
			}
		case reflect.Interface:
			fallthrough
		case reflect.Ptr:
			for i := 0; i < v.Len(); i++ {
				model := v.Index(i).Interface()
				err := do(model)
				if err != nil {
					return err
				}
			}
		default:
			panic(fmt.Sprintf("Expected slice of pointers or structs but got %s", v.Type().Elem().Kind()))
		}
	case reflect.Struct:
		err := do(models)
		if err != nil {
			return err
		}
	default:
		panic(fmt.Sprintf("Expected slice or struct but got %s", v.Kind()))
	}
	return nil
}
