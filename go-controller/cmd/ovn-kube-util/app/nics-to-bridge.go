package app

import (
	"fmt"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/util/errors"
	kexec "k8s.io/utils/exec"
)

// NicsToBridgeCommand creates ovs bridge for provided nic interfaces.
var NicsToBridgeCommand = cli.Command{
	Name:  "nics-to-bridge",
	Usage: "Create ovs bridge for nic interfaces",
	Flags: []cli.Flag{},
	Action: func(context *cli.Context) error {
		args := context.Args()
		if args.Len() == 0 {
			return fmt.Errorf("Please specify list of nic interfaces")
		}

		if err := util.SetSpecificExec(kexec.New(), "ovs-vsctl"); err != nil {
			return err
		}

		var errorList []error
		for _, nic := range args.Slice() {
			if _, err := util.NicToBridge(nic); err != nil {
				errorList = append(errorList, err)
			}
		}

		return errors.NewAggregate(errorList)
	},
}

// BridgesToNicCommand removes a NIC interface from OVS bridge and deletes the bridge
var BridgesToNicCommand = cli.Command{
	Name:  "bridges-to-nic",
	Usage: "Delete ovs bridge and move IP/routes to underlying NIC",
	Flags: []cli.Flag{},
	Action: func(context *cli.Context) error {
		args := context.Args()
		if args.Len() == 0 {
			return fmt.Errorf("Please specify list of bridges")
		}

		if err := util.SetSpecificExec(kexec.New(), "ovs-vsctl"); err != nil {
			return err
		}

		var errorList []error
		for _, bridge := range args.Slice() {
			if err := util.BridgeToNic(bridge); err != nil {
				errorList = append(errorList, err)
			}
		}

		return errors.NewAggregate(errorList)
	},
}
