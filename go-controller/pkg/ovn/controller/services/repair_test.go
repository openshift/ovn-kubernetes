package services

import (
	"testing"

	ovntest "github.com/ovn-org/ovn-kubernetes/go-controller/pkg/testing"
	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/util"
	v1 "k8s.io/api/core/v1"
)

const (
	tcpLBUUID    string = "1a3dfc82-2749-4931-9190-c30e7c0ecea3"
	udpLBUUID    string = "6d3142fc-53e8-4ac1-88e6-46094a5a9957"
	sctpLBUUID   string = "0514c521-a120-4756-aec6-883fe5db7139"
	grTcpLBUUID  string = "001c2ec6-2f32-11eb-9bc2-a8a1590cda29"
	grUdpLBUUID  string = "05c55ae6-2f32-11eb-822e-a8a1590cda29"
	grSctpLBUUID string = "0ac92874-2f32-11eb-8ca0-a8a1590cda29"
)

func TestRepair_Empty(t *testing.T) {
	st := newServiceTracker()
	r := &Repair{
		interval:       0,
		serviceTracker: st,
	} // Expected OVN commands
	fexec := ovntest.NewFakeExec()
	initializeClusterIPLBs(fexec)
	// OVN is empty
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + sctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grSctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + tcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grTcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + udpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grUdpLBUUID + " vips",
		Output: "",
	})

	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	if err := r.runOnce(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestRepair_OVNStaleData(t *testing.T) {
	st := newServiceTracker()
	r := &Repair{
		interval:       0,
		serviceTracker: st,
	} // Expected OVN commands
	fexec := ovntest.NewLooseCompareFakeExec()
	initializeClusterIPLBs(fexec)
	// There are remaining OVN LB that doesn't exist in Kubernetes
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + sctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grSctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + tcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grTcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + udpLBUUID + " vips",
		Output: `{"10.96.0.10:53"="10.244.2.3:53,10.244.2.5:53", "10.96.0.10:9153"="10.244.2.3:9153,10.244.2.5:9153", "10.96.0.1:443"="172.19.0.3:6443"}`,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grUdpLBUUID + " vips",
		Output: "",
	})
	// The repair loop must delete the remaining entries in OVN
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer " + udpLBUUID + " vips \"10.96.0.10:53\"",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer " + udpLBUUID + " vips \"10.96.0.10:9153\"",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --if-exists remove load_balancer " + udpLBUUID + " vips \"10.96.0.1:443\"",
		Output: "",
	})
	// The repair loop must delete them
	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	if err := r.runOnce(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestRepair_OVNSynced(t *testing.T) {
	st := newServiceTracker()
	r := &Repair{
		interval:       0,
		serviceTracker: st,
	}
	// Expected OVN commands
	fexec := ovntest.NewLooseCompareFakeExec()
	initializeClusterIPLBs(fexec)

	st.updateService("svcname", "nsname", "10.96.0.10:80", v1.ProtocolTCP)
	st.updateService("svcname", "nsname", "[fd00:10:96::1]:80", v1.ProtocolTCP)

	// OVN database is in Sync no operation expected
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + sctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grSctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + tcpLBUUID + " vips",
		Output: `{"10.96.0.10:80"="10.0.0.2:3456,10.0.0.3:3456", "[fd00:10:96::1]:80"="[2001:db8::1]:3456,[2001:db8::2]:3456"}`,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grTcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + udpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grUdpLBUUID + " vips",
		Output: "",
	})

	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	if err := r.runOnce(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestRepair_OVNMissingService(t *testing.T) {
	st := newServiceTracker()
	r := &Repair{
		interval:       0,
		serviceTracker: st,
	} // Expected OVN commands
	fexec := ovntest.NewFakeExec()
	initializeClusterIPLBs(fexec)

	r.serviceTracker.updateService("svcname", "nsname", "10.96.0.10:80", v1.ProtocolTCP)
	r.serviceTracker.updateService("svcname", "nsname", "[fd00:10:96::1]:80", v1.ProtocolTCP)

	// OVN database is in Sync no operation expected
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + sctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grSctpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + tcpLBUUID + " vips",
		Output: `{"10.96.0.10:80"="10.0.0.2:3456,10.0.0.3:3456"}`,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grTcpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + udpLBUUID + " vips",
		Output: "",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading get load_balancer " + grUdpLBUUID + " vips",
		Output: "",
	})

	// The repair loop must do nothing, the controller will add the new service
	err := util.SetExec(fexec)
	if err != nil {
		t.Errorf("fexec error: %v", err)
	}

	if err := r.runOnce(); err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
}

func initializeClusterIPLBs(fexec *ovntest.FakeExec) {
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-sctp=yes",
		Output: sctpLBUUID,
	})

	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-tcp=yes",
		Output: tcpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:k8s-cluster-lb-udp=yes",
		Output: udpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=name find logical_router options:chassis!=null",
		Output: "gateway1",
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:SCTP_lb_gateway_router=gateway1",
		Output: grSctpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:TCP_lb_gateway_router=gateway1",
		Output: grTcpLBUUID,
	})
	fexec.AddFakeCmd(&ovntest.ExpectedCmd{
		Cmd:    "ovn-nbctl --timeout=15 --data=bare --no-heading --columns=_uuid find load_balancer external_ids:UDP_lb_gateway_router=gateway1",
		Output: grUdpLBUUID,
	})
}
