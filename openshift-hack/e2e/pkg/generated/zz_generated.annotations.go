package generated

import (
	"fmt"
	"github.com/onsi/ginkgo/v2"
	"github.com/onsi/ginkgo/v2/types"
)

var AppendedAnnotations = map[string]string{
	"ACL Logging for AdminNetworkPolicy and BaselineAdminNetworkPolicy the ANP ACL logs have the expected log level": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when an invalid value is provided to the allow rule when the allowed destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when an invalid value is provided to the allow rule when the denied destination is poked the logs should have the expected log level": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when both the namespace's ACL logging deny and allow annotation are set to \"\" when the allowed destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when both the namespace's ACL logging deny and allow annotation are set to \"\" when the denied destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when both the namespace's ACL logging deny and allow annotation are set to \"invalid\" when the allowed destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when both the namespace's ACL logging deny and allow annotation are set to \"invalid\" when the denied destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace is brought up with the initial ACL log severity when the allowed destination is poked the logs should have the expected log level": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace is brought up with the initial ACL log severity when the denied destination is poked the logs should have the expected log level": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's ACL logging allow annotation is removed when the allowed destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's ACL logging allow annotation is removed when the denied destination is poked the logs should have the expected log level": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's ACL logging annotation cannot be parsed when the allowed destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's ACL logging annotation cannot be parsed when the denied destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's ACL logging annotation is updated when the allowed destination is poked the logs should have the expected log level": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's ACL logging annotation is updated when the denied destination is poked the logs should have the expected log level": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's entire ACL logging annotation is removed when the allowed destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's entire ACL logging annotation is removed when the denied destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's entire ACL logging annotation is set to {} when the allowed destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for EgressFirewall when the namespace's entire ACL logging annotation is set to {} when the denied destination is poked there should be no trace in the ACL logs": "[Disabled:Unimplemented]",

	"ACL Logging for NetworkPolicy the logs have the expected log level": "[Disabled:Unimplemented]",

	"ACL Logging for NetworkPolicy when the namespace's ACL allow and deny logging annotations are set to invalid values ACL logging is disabled": "[Disabled:Unimplemented]",

	"ACL Logging for NetworkPolicy when the namespace's ACL logging annotation is removed ACL logging is disabled": "[Disabled:Unimplemented]",

	"ACL Logging for NetworkPolicy when the namespace's ACL logging annotation is updated the ACL logs are updated accordingly": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network Can reach KAPI service": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It can be reached by an external server on the same network When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It can be reached by an external server on the same network When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It can reach an external server on the same network When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It can reach an external server on the same network When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It cannot be reached by a cluster node When it is a different node When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It cannot be reached by a cluster node When it is a different node When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It cannot be reached by a cluster node When it is the same node When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It cannot be reached by a cluster node When it is the same node When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It cannot be reached by an external server on a different network When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It cannot be reached by an external server on a different network When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It cannot reach an external server on a different network When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network It cannot reach an external server on a different network When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When other pod runs on the tested network On a different node Backing a ClusterIP service The first pod can reach the ClusterIP service on the same network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When other pod runs on the tested network On a different node Backing a ClusterIP service The first pod can reach the ClusterIP service on the same network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When other pod runs on the tested network On a different node The pods on the tested network can reach each other When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When other pod runs on the tested network On a different node The pods on the tested network can reach each other When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When other pod runs on the tested network On the same node Backing a ClusterIP service The first pod can reach the ClusterIP service on the same network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When other pod runs on the tested network On the same node Backing a ClusterIP service The first pod can reach the ClusterIP service on the same network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When other pod runs on the tested network On the same node The pods on the tested network can reach each other When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When other pod runs on the tested network On the same node The pods on the tested network can reach each other When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 2 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network Can reach KAPI service": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It can be reached by an external server on the same network When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It can be reached by an external server on the same network When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It can reach an external server on the same network When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It can reach an external server on the same network When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It cannot be reached by a cluster node When it is a different node When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It cannot be reached by a cluster node When it is a different node When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It cannot be reached by a cluster node When it is the same node When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It cannot be reached by a cluster node When it is the same node When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It cannot be reached by an external server on a different network When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It cannot be reached by an external server on a different network When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It cannot reach an external server on a different network When the network is IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network It cannot reach an external server on a different network When the network is IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When other pod runs on the tested network On a different node Backing a ClusterIP service The first pod can reach the ClusterIP service on the same network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When other pod runs on the tested network On a different node Backing a ClusterIP service The first pod can reach the ClusterIP service on the same network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When other pod runs on the tested network On a different node The pods on the tested network can reach each other When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When other pod runs on the tested network On a different node The pods on the tested network can reach each other When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When other pod runs on the tested network On the same node Backing a ClusterIP service The first pod can reach the ClusterIP service on the same network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When other pod runs on the tested network On the same node Backing a ClusterIP service The first pod can reach the ClusterIP service on the same network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When other pod runs on the tested network On the same node The pods on the tested network can reach each other When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When other pod runs on the tested network On the same node The pods on the tested network can reach each other When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Default And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 2 UDN non advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 CUDN advertised VRF-Lite And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On a different node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node Backing a ClusterIP service The pod on the tested network cannot reach the service on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node The pod on the other network cannot reach the pod on the tested network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv4": "[Disabled:Unimplemented]",

	"BGP: For a VRF-Lite configured network When the tested network is of type Layer 3 When a pod runs on the tested network When there is other network Of type Layer 3 UDN non advertised And a pod runs on the other network On the same node The pod on the tested network cannot reach the pod on the other network When the networks are IPv6": "[Disabled:Unimplemented]",

	"BGP: Pod to external server when CUDN network is advertised Route Advertisements layer2": "[Disabled:Unimplemented]",

	"BGP: Pod to external server when CUDN network is advertised Route Advertisements layer3": "[Disabled:Unimplemented]",

	"BGP: Pod to external server when default podNetwork is advertised when a client ovnk pod targeting an external server is created tests are run towards the external agnhost echo server": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks UDN pod to a different node nodeport service in default network should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks UDN pod to a different node nodeport service in different UDN network should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks UDN pod to a different node nodeport service in same UDN network should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks UDN pod to a different node should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks UDN pod to local node should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks UDN pod to the same node nodeport service in default network should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks UDN pod to the same node nodeport service in different UDN network should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks UDN pod to the same node nodeport service in same UDN network should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks host to a different node UDN pod should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks host to a local UDN pod should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod in the UDN should be able to access a service in the same network": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod in the UDN should be able to access kapi in default network service": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod in the UDN should not be able to access a default network service": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod in the UDN should not be able to access a service in a different UDN": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod in the default network should not be able to access a UDN service": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod in the default network should not be able to access an advertised UDN pod on a different node": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod in the default network should not be able to access an advertised UDN pod on the same node": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod to pod connectivity on different networks and different nodes": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod to pod connectivity on different networks and same node": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod to pod on the same network and different nodes should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer2 connectivity between networks pod to pod on the same network and same node should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks UDN pod to a different node nodeport service in default network should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks UDN pod to a different node nodeport service in different UDN network should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks UDN pod to a different node nodeport service in same UDN network should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks UDN pod to a different node should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks UDN pod to local node should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks UDN pod to the same node nodeport service in default network should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks UDN pod to the same node nodeport service in different UDN network should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks UDN pod to the same node nodeport service in same UDN network should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks host to a different node UDN pod should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks host to a local UDN pod should not work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod in the UDN should be able to access a service in the same network": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod in the UDN should be able to access kapi in default network service": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod in the UDN should not be able to access a default network service": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod in the UDN should not be able to access a service in a different UDN": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod in the default network should not be able to access a UDN service": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod in the default network should not be able to access an advertised UDN pod on a different node": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod in the default network should not be able to access an advertised UDN pod on the same node": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod to pod connectivity on different networks and different nodes": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod to pod connectivity on different networks and same node": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod to pod on the same network and different nodes should work": "[Disabled:Unimplemented]",

	"BGP: isolation between advertised networks Layer3 connectivity between networks pod to pod on the same network and same node should work": "[Disabled:Unimplemented]",

	"Check whether gateway-mtu-support annotation on node is set based on disable-pkt-mtu-check value when DisablePacketMTUCheck is either not set or set to false Verify whether gateway-mtu-support annotation is not set on nodes when DisablePacketMTUCheck is either not set or set to false": "[Disabled:Unimplemented]",

	"Creating a static pod on a node Should successfully create then remove a static pod": "[Disabled:Unimplemented]",

	"EgressService Multiple Networks, external clients sharing ip [LGW] Should validate pods on different networks can reach different clients with same ip without SNAT ipv4 pods": "[Disabled:Unimplemented]",

	"EgressService Multiple Networks, external clients sharing ip [LGW] Should validate pods on different networks can reach different clients with same ip without SNAT ipv6 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate a node with a local ep is selected when ETP=Local ipv4 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate a node with a local ep is selected when ETP=Local ipv6 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate egress service has higher priority than EgressIP when not assigned to the same node ipv4 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate egress service has higher priority than EgressIP when not assigned to the same node ipv6 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate pods' egress is SNATed to the LB's ingress ip with selectors ipv4 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate pods' egress is SNATed to the LB's ingress ip with selectors ipv6 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate pods' egress is SNATed to the LB's ingress ip without selectors ipv4 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate pods' egress is SNATed to the LB's ingress ip without selectors ipv6 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate the egress SVC SNAT functionality against host-networked pods ipv4 pods": "[Disabled:Unimplemented]",

	"EgressService Should validate the egress SVC SNAT functionality against host-networked pods ipv6 pods": "[Disabled:Unimplemented]",

	"EgressService [LGW] Should validate ingress reply traffic uses the Network ipv4 pods": "[Disabled:Unimplemented]",

	"EgressService [LGW] Should validate ingress reply traffic uses the Network ipv6 pods": "[Disabled:Unimplemented]",

	"EgressService [LGW] Should validate pods' egress uses node's IP when setting Network without SNAT ipv4 pods": "[Disabled:Unimplemented]",

	"EgressService [LGW] Should validate pods' egress uses node's IP when setting Network without SNAT ipv6 pods": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry remains unchanged when deleting the annotation in the pods while the CR dynamic hop still references the same pods with the pod selector IPV4 tcp": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry remains unchanged when deleting the annotation in the pods while the CR dynamic hop still references the same pods with the pod selector IPV4 udp": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry remains unchanged when deleting the annotation in the pods while the CR dynamic hop still references the same pods with the pod selector IPV6 tcp": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry remains unchanged when deleting the annotation in the pods while the CR dynamic hop still references the same pods with the pod selector IPV6 udp": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Namespace annotation: Should validate conntrack entry remains unchanged when deleting the annotation in the namespace while the CR static hop still references the same namespace in the policy IPV4 tcp": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Namespace annotation: Should validate conntrack entry remains unchanged when deleting the annotation in the namespace while the CR static hop still references the same namespace in the policy IPV4 udp": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Namespace annotation: Should validate conntrack entry remains unchanged when deleting the annotation in the namespace while the CR static hop still references the same namespace in the policy IPV6 tcp": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Namespace annotation: Should validate conntrack entry remains unchanged when deleting the annotation in the namespace while the CR static hop still references the same namespace in the policy IPV6 udp": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate ICMP connectivity to an external gateway's loopback address via a pod with external gateway annotations and a policy CR and after the annotations are removed ipv4": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod when deleting the annotation and supported by a CR with the same gateway IPs TCP ipv4": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod when deleting the annotation and supported by a CR with the same gateway IPs TCP ipv6": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod when deleting the annotation and supported by a CR with the same gateway IPs UDP ipv4": "[Disabled:Unimplemented]",

	"External Gateway When migrating from Annotations to Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod when deleting the annotation and supported by a CR with the same gateway IPs UDP ipv6": "[Disabled:Unimplemented]",

	"External Gateway When validating the Admin Policy Based External Route status Should update the status of a successful and failed CRs": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e multiple external gateway validation Should validate ICMP connectivity to multiple external gateways for an ECMP scenario IPV4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e multiple external gateway validation Should validate ICMP connectivity to multiple external gateways for an ECMP scenario IPV6": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV4 tcp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV4 udp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV6 tcp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV6 udp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e non-vxlan external gateway through a dynamic hop Should validate ICMP connectivity to an external gateway's loopback address via a pod with dynamic hop ipv4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e non-vxlan external gateway through a dynamic hop Should validate ICMP connectivity to an external gateway's loopback address via a pod with dynamic hop ipv6": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e non-vxlan external gateway through a dynamic hop Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with a dynamic hop TCP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e non-vxlan external gateway through a dynamic hop Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with a dynamic hop TCP ipv6": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e non-vxlan external gateway through a dynamic hop Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with a dynamic hop UDP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs BFD e2e non-vxlan external gateway through a dynamic hop Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with a dynamic hop UDP ipv6": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 tcp + pod annotation update": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 tcp + pod deletion timestamp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 tcp + pod not ready": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 udp + pod annotation update": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 udp + pod deletion timestamp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 udp + pod not ready": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 tcp + pod annotation update": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 tcp + pod deletion timestamp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 tcp + pod not ready": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 udp + pod annotation update": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 udp + pod deletion timestamp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Dynamic Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 udp + pod not ready": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Static Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 tcp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Static Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 udp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Static Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 tcp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway stale conntrack entry deletion validation Static Hop: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 udp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway validation Should validate ICMP connectivity to multiple external gateways for an ECMP scenario IPV4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway validation Should validate ICMP connectivity to multiple external gateways for an ECMP scenario IPV6": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV4 tcp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV4 udp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV6 tcp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV6 udp": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate ICMP connectivity to an external gateway's loopback address via a gateway pod ipv4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate ICMP connectivity to an external gateway's loopback address via a gateway pod ipv6": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity even after MAC change (gateway migration) for egress TCP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity even after MAC change (gateway migration) for egress TCP ipv6": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity even after MAC change (gateway migration) for egress UDP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity even after MAC change (gateway migration) for egress UDP ipv6": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a gateway pod TCP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a gateway pod TCP ipv6": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a gateway pod UDP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With Admin Policy Based External Route CRs e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a gateway pod UDP ipv6": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e multiple external gateway validation Should validate ICMP connectivity to multiple external gateways for an ECMP scenario IPV4": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e multiple external gateway validation Should validate ICMP connectivity to multiple external gateways for an ECMP scenario IPV6": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV4 tcp": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV4 udp": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV6 tcp": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV6 udp": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e non-vxlan external gateway through an annotated gateway pod Should validate ICMP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled ipv4": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e non-vxlan external gateway through an annotated gateway pod Should validate ICMP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled ipv6": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e non-vxlan external gateway through an annotated gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled TCP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e non-vxlan external gateway through an annotated gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled TCP ipv6": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e non-vxlan external gateway through an annotated gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled UDP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With annotations BFD e2e non-vxlan external gateway through an annotated gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled UDP ipv6": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 tcp + pod annotation update": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 tcp + pod deletion timestamp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 tcp + pod not ready": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 udp + pod annotation update": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 udp + pod delete": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 udp + pod deletion timestamp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 udp + pod not ready": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 tcp + pod annotation update": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 tcp + pod delete": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 tcp + pod deletion timestamp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 tcp + pod not ready": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 udp + pod annotation update": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 udp + pod deletion timestamp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation ExternalGWPod annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 udp + pod not ready": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation Namespace annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 tcp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation Namespace annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV4 udp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation Namespace annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 tcp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway stale conntrack entry deletion validation Namespace annotation: Should validate conntrack entry deletion for TCP/UDP traffic via multiple external gateways a.k.a ECMP routes IPV6 udp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway validation Should validate ICMP connectivity to multiple external gateways for an ECMP scenario IPV4": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway validation Should validate ICMP connectivity to multiple external gateways for an ECMP scenario IPV6": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV4 tcp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV4 udp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV6 tcp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e multiple external gateway validation Should validate TCP/UDP connectivity to multiple external gateways for a UDP / TCP scenario IPV6 udp": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e non-vxlan external gateway through a gateway pod Should validate ICMP connectivity to an external gateway's loopback address via a pod with external gateway CR ipv4": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e non-vxlan external gateway through a gateway pod Should validate ICMP connectivity to an external gateway's loopback address via a pod with external gateway CR ipv6": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled TCP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled TCP ipv6": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled UDP ipv4": "[Disabled:Unimplemented]",

	"External Gateway With annotations e2e non-vxlan external gateway through a gateway pod Should validate TCP/UDP connectivity to an external gateway's loopback address via a pod with external gateway annotations enabled UDP ipv6": "[Disabled:Unimplemented]",

	"External Gateway e2e ingress gateway traffic validation Should validate ingress connectivity from an external gateway": "[Disabled:Unimplemented]",

	"External Gateway e2e non-vxlan external gateway and update validation Should validate connectivity without vxlan before and after updating the namespace annotation to a new external gateway": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with default pod network when live migration with post-copy succeeds, should keep connectivity": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with default pod network when live migration with pre-copy fails, should keep connectivity": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with default pod network when live migration with pre-copy succeeds, should keep connectivity": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with kubevirt VM using layer2 UDPN should configure IPv4 and IPv6 using DHCP and NDP": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration failed of VirtualMachineInstance with Secondary/Localnet with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration failed of VirtualMachineInstance with interface binding for UDN with Primary/Layer2 with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration of VirtualMachine with Secondary/Layer2 with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration of VirtualMachine with Secondary/Localnet with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration of VirtualMachine with interface binding for UDN and statics IPs and MAC with Primary/Layer2 with routed ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration of VirtualMachine with interface binding for UDN and statics IPs and MAC with Primary/Layer2 with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration of VirtualMachine with interface binding for UDN with Primary/Layer2 with routed ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration of VirtualMachine with interface binding for UDN with Primary/Layer2 with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration of VirtualMachineInstance with Secondary/Layer2 with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration of VirtualMachineInstance with Secondary/Localnet with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after live migration of VirtualMachineInstance with interface binding for UDN with Primary/Layer2 with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after restart of VirtualMachine with Secondary/Layer2 with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after restart of VirtualMachine with Secondary/Localnet with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after restart of VirtualMachine with interface binding for UDN and statics IPs and MAC with Primary/Layer2 with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks and persistent ips configured should keep ip after restart of VirtualMachine with interface binding for UDN with Primary/Layer2 with snat ingress": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks with ipamless localnet topology should maintain tcp connection with minimal downtime after failed live migration": "[Disabled:Unimplemented]",

	"Kubevirt Virtual Machines with user defined networks with ipamless localnet topology should maintain tcp connection with minimal downtime after succeeded live migration": "[Disabled:Unimplemented]",

	"Load Balancer Service Tests with MetalLB Should ensure connectivity works on an external service when mtu changes in intermediate node": "[Disabled:Unimplemented]",

	"Load Balancer Service Tests with MetalLB Should ensure load balancer service works when ETP=local and backend pods are also egressIP served pods": "[Disabled:Unimplemented]",

	"Load Balancer Service Tests with MetalLB Should ensure load balancer service works when ETP=local and session affinity is set": "[Disabled:Unimplemented]",

	"Load Balancer Service Tests with MetalLB Should ensure load balancer service works with 0 node ports when ETP=local": "[Disabled:Unimplemented]",

	"Load Balancer Service Tests with MetalLB Should ensure load balancer service works with pmtud": "[Disabled:Unimplemented]",

	"Multi Homing A pod with multiple attachments to the same OVN-K networks features two different IPs from the same subnet": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network attached to a localnet network mapped to external primary interface bridge can be reached by a client pod in the default network on a different node": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network attached to a localnet network mapped to external primary interface bridge can be reached by a client pod in the default network on the same node": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network attached to a localnet network mapped to external primary interface bridge can reach a host-networked pod on a different node": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network attached to a localnet network mapped to external primary interface bridge can reach a host-networked pod on the same node": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to a localnet - switched - network featuring `excludeCIDR`s": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to a localnet - switched - network with an IPv6 subnet": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to a localnet - switched - network without IPAM": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to a localnet - switched - network": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to an L2 - switched - network featuring `excludeCIDR`s": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to an L2 - switched - network with a dual stack configuration": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to an L2 - switched - network with an IPv6 subnet": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to an L2 - switched - network without IPAM": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to an L2 - switched - network": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to an L3 - routed - network with IPv6 network": "[Disabled:Unimplemented]",

	"Multi Homing A single pod with an OVN-K secondary network is able to get to the Running phase when attaching to an L3 - routed - network": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over a localnet secondary network when the pods are scheduled on different nodes": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over a localnet secondary network with a dual stack configuration when pods are scheduled on different nodes": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over a localnet secondary network with an IPv6 subnet when pods are scheduled on different nodes": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over a localnet secondary network without IPAM when the pods are scheduled on different nodes": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over a localnet secondary network without IPAM when the pods are scheduled on different nodes, with static IPs configured via network selection elements": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over an L2 - switched - secondary network with `excludeCIDR`s": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over an L2 - switched - secondary network without IPAM": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over an L2 secondary network when the pods are scheduled in different nodes": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over an L2 secondary network with a dual stack configuration": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over an L2 secondary network with an IPv6 subnet when pods are scheduled in different nodes": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over an L2 secondary network without IPAM, with static IPs configured via network selection elements": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over an L3 - routed - secondary network with IPv6 subnet": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over an L3 - routed - secondary network with a dual stack configuration": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network can communicate over the secondary network can communicate over an L3 - routed - secondary network": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network eventually configures pods that were added to an already existing network before the nad": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay and networkAttachmentDefinition is modified allocates the pod's secondary interface IP in the new range after NetworkAttachmentDefinition reconcile": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay and networkAttachmentDefinition is modified and the service connected to the underlay is reconfigured to connect to the new VLAN-ID can now communicate over a localnet secondary network from pod to the underlay service": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay and networkAttachmentDefinition is modified can no longer communicate over a localnet secondary network from pod to the underlay service": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay and networkAttachmentDefinition is modified sets the new MTU on the pod after NetworkAttachmentDefinition reconcile": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay can communicate over a localnet secondary network from pod to the underlay service": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay correctly sets the MTU on the pod": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay when a policy is provisioned can communicate over a localnet secondary network from pod to gw egress allow all": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay when a policy is provisioned can communicate over a localnet secondary network from pod to gw egress deny all": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay when a policy is provisioned can communicate over a localnet secondary network from pod to gw ingress denyall, egress allow all, ingress policy should have no impact on egress": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay when a policy is provisioned can communicate over a localnet secondary network from pod to gw ingress denyall, ingress policy should have no impact on egress": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a service running on the underlay with multi network policy blocking the traffic can not communicate over a localnet secondary network from pod to the underlay service": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network localnet OVN-K secondary network with a trunked configuration the same bridge mapping can be shared by a separate VLAN by using the physical network name attribute": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that allow all ingress using egress deny-all for a localnet topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that allow all ingress using egress deny-all, ingress allow-all for a localnet topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that allow all ingress using ingress allow-all for a localnet topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using IPBlock for a localnet topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using IPBlock for a pure L2 overlay": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using IPBlock for a routed topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using IPBlock for an IPAMless pure L2 overlay": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using namespace selectors for a localnet topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using namespace selectors for a pure L2 overlay": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using namespace selectors for a routed topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using pod selectors and port range for a pure L2 overlay": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using pod selectors for a localnet topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using pod selectors for a pure L2 overlay": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that configure traffic allow lists using pod selectors for a routed topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that deny traffic using ingress deny-all for a localnet topology": "[Disabled:Unimplemented]",

	"Multi Homing multiple pods connected to the same OVN-K secondary network with multi-network policies that deny traffic using pod selectors and wrong port range for a localnet topology": "[Disabled:Unimplemented]",

	"Multi node zones interconnect Pod interconnectivity": "[Disabled:Unimplemented]",

	"Multicast when multicast enabled for namespace should be able to receive multicast IGMP query": "[Disabled:Unimplemented]",

	"Multicast when multicast enabled for namespace should be able to send multicast UDP traffic between nodes": "[Disabled:Unimplemented]",

	"Network Segmentation ClusterUserDefinedNetwork CRD Controller pod connected to ClusterUserDefinedNetwork CR & managed NADs cannot be deleted when being used": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation ClusterUserDefinedNetwork CRD Controller should create NAD according to spec in each target namespace and report active namespaces": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation ClusterUserDefinedNetwork CRD Controller should create NAD in new created namespaces that apply to namespace-selector": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation ClusterUserDefinedNetwork CRD Controller when CR is deleted, should delete all managed NAD in each target namespace": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation ClusterUserDefinedNetwork CRD Controller when namespace-selector is mutated should create NAD in namespaces that apply to mutated namespace-selector": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation ClusterUserDefinedNetwork CRD Controller when namespace-selector is mutated should delete managed NAD in namespaces that no longer apply to namespace-selector": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using NetworkAttachmentDefinitions does not mirror EndpointSlices in namespaces not using user defined primary networks L2 secondary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using NetworkAttachmentDefinitions does not mirror EndpointSlices in namespaces not using user defined primary networks L3 secondary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using NetworkAttachmentDefinitions mirrors EndpointSlices managed by the default controller for namespaces with user defined primary networks L2 primary UDN, cluster-networked pods": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using NetworkAttachmentDefinitions mirrors EndpointSlices managed by the default controller for namespaces with user defined primary networks L2 primary UDN, host-networked pods": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using NetworkAttachmentDefinitions mirrors EndpointSlices managed by the default controller for namespaces with user defined primary networks L3 primary UDN, cluster-networked pods": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using NetworkAttachmentDefinitions mirrors EndpointSlices managed by the default controller for namespaces with user defined primary networks L3 primary UDN, host-networked pods": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using UserDefinedNetwork does not mirror EndpointSlices in namespaces not using user defined primary networks L2 secondary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using UserDefinedNetwork does not mirror EndpointSlices in namespaces not using user defined primary networks L3 secondary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using UserDefinedNetwork mirrors EndpointSlices managed by the default controller for namespaces with user defined primary networks L2 primary UDN, cluster-networked pods": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using UserDefinedNetwork mirrors EndpointSlices managed by the default controller for namespaces with user defined primary networks L2 primary UDN, host-networked pods": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using UserDefinedNetwork mirrors EndpointSlices managed by the default controller for namespaces with user defined primary networks L3 primary UDN, cluster-networked pods": "[Disabled:Unimplemented]",

	"Network Segmentation EndpointSlices mirroring a user defined primary network created using UserDefinedNetwork mirrors EndpointSlices managed by the default controller for namespaces with user defined primary networks L3 primary UDN, host-networked pods": "[Disabled:Unimplemented]",

	"Network Segmentation Sync perform east/west traffic between nodes following OVN Kube node pod restart L2 with custom network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation Sync perform east/west traffic between nodes following OVN Kube node pod restart L2": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation Sync perform east/west traffic between nodes following OVN Kube node pod restart L3": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation UDN Pod should react to k8s.ovn.org/open-default-ports annotations changes": "[Disabled:Unimplemented]",

	"Network Segmentation UserDefinedNetwork CRD Controller for L2 secondary network pod connected to UserDefinedNetwork cannot be deleted when being used": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation UserDefinedNetwork CRD Controller for L2 secondary network should create NetworkAttachmentDefinition according to spec": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation UserDefinedNetwork CRD Controller for L2 secondary network should delete NetworkAttachmentDefinition when UserDefinedNetwork is deleted": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation UserDefinedNetwork CRD Controller for primary UDN without required namespace label should be able to create pod and it will attach to the cluster default network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation UserDefinedNetwork CRD Controller for primary UDN without required namespace label should not be able to update the namespace and add the UDN label": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation UserDefinedNetwork CRD Controller for primary UDN without required namespace label should not be able to update the namespace and remove the UDN label": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation UserDefinedNetwork CRD Controller should correctly report subsystem error on node subnet allocation": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L2 primary UDN with custom network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L2 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L3 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork creates a networkStatus Annotation with UDN interface L2 primary UDN with custom network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork creates a networkStatus Annotation with UDN interface L2 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork creates a networkStatus Annotation with UDN interface L3 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork is isolated from the default network with L2 primary UDN with custom network": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork is isolated from the default network with L2 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork is isolated from the default network with L3 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork isolates overlapping CIDRs with L2 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using ClusterUserDefinedNetwork isolates overlapping CIDRs with L3 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions can perform east/west traffic between nodes two pods connected over a L2 primary UDN with custom network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions can perform east/west traffic between nodes two pods connected over a L2 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions can perform east/west traffic between nodes two pods connected over a L3 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions creates a networkStatus Annotation with UDN interface L2 primary UDN with custom network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions creates a networkStatus Annotation with UDN interface L2 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions creates a networkStatus Annotation with UDN interface L3 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions is isolated from the default network with L2 primary UDN with custom network": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions is isolated from the default network with L2 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions is isolated from the default network with L3 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions isolates overlapping CIDRs with L2 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using NetworkAttachmentDefinitions isolates overlapping CIDRs with L3 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L2 primary UDN with custom network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L2 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork can perform east/west traffic between nodes two pods connected over a L3 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork creates a networkStatus Annotation with UDN interface L2 primary UDN with custom network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork creates a networkStatus Annotation with UDN interface L2 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork creates a networkStatus Annotation with UDN interface L3 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork is isolated from the default network with L2 primary UDN with custom network": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork is isolated from the default network with L2 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork is isolated from the default network with L3 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork isolates overlapping CIDRs with L2 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network created using UserDefinedNetwork isolates overlapping CIDRs with L3 primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network doesn't cause network name conflict": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network with multicast feature enabled for namespace should be able to receive multicast IGMP query with primary layer3 UDN": "[Disabled:Unimplemented]",

	"Network Segmentation a user defined primary network with multicast feature enabled for namespace should be able to send multicast UDP traffic between nodes with primary layer2 UDN with custom network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network with multicast feature enabled for namespace should be able to send multicast UDP traffic between nodes with primary layer2 UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation a user defined primary network with multicast feature enabled for namespace should be able to send multicast UDP traffic between nodes with primary layer3 UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation pod2Egress on a user defined primary network created using ClusterUserDefinedNetwork can be accessed to from the pods running in the Kubernetes cluster by one pod over a layer2 network with custom network": "[Disabled:Unimplemented]",

	"Network Segmentation pod2Egress on a user defined primary network created using ClusterUserDefinedNetwork can be accessed to from the pods running in the Kubernetes cluster by one pod over a layer2 network": "[Disabled:Unimplemented]",

	"Network Segmentation pod2Egress on a user defined primary network created using ClusterUserDefinedNetwork can be accessed to from the pods running in the Kubernetes cluster by one pod over a layer3 network": "[Disabled:Unimplemented]",

	"Network Segmentation pod2Egress on a user defined primary network created using NetworkAttachmentDefinitions can be accessed to from the pods running in the Kubernetes cluster by one pod over a layer2 network with custom network": "[Disabled:Unimplemented]",

	"Network Segmentation pod2Egress on a user defined primary network created using NetworkAttachmentDefinitions can be accessed to from the pods running in the Kubernetes cluster by one pod over a layer2 network": "[Disabled:Unimplemented]",

	"Network Segmentation pod2Egress on a user defined primary network created using NetworkAttachmentDefinitions can be accessed to from the pods running in the Kubernetes cluster by one pod over a layer3 network": "[Disabled:Unimplemented]",

	"Network Segmentation pod2Egress on a user defined primary network created using UserDefinedNetwork can be accessed to from the pods running in the Kubernetes cluster by one pod over a layer2 network with custom network": "[Disabled:Unimplemented]",

	"Network Segmentation pod2Egress on a user defined primary network created using UserDefinedNetwork can be accessed to from the pods running in the Kubernetes cluster by one pod over a layer2 network": "[Disabled:Unimplemented]",

	"Network Segmentation pod2Egress on a user defined primary network created using UserDefinedNetwork can be accessed to from the pods running in the Kubernetes cluster by one pod over a layer3 network": "[Disabled:Unimplemented]",

	"Network Segmentation when primary network exist, ClusterUserDefinedNetwork status should report not-ready": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation when primary network exist, UserDefinedNetwork status should report not-ready": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: API validations api-server should accept valid CRs ClusterUserDefinedNetwork, layer2": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should accept valid CRs ClusterUserDefinedNetwork, localnet": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should accept valid CRs UserDefinedNetwork, layer2": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should reject invalid CRs ClusterUserDefinedNetwork, layer2": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should reject invalid CRs ClusterUserDefinedNetwork, localnet, invalid mtu": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should reject invalid CRs ClusterUserDefinedNetwork, localnet, invalid physicalNetworkName": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should reject invalid CRs ClusterUserDefinedNetwork, localnet, invalid role": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should reject invalid CRs ClusterUserDefinedNetwork, localnet, invalid subnets": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should reject invalid CRs ClusterUserDefinedNetwork, localnet, invalid vlan": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should reject invalid CRs ClusterUserDefinedNetwork, mismatch topology and config": "[Disabled:Unimplemented]",

	"Network Segmentation: API validations api-server should reject invalid CRs UserDefinedNetwork, layer2": "[Disabled:Unimplemented]",

	"Network Segmentation: Default network multus annotation ValidatingAdmissionPolicy protection should prevent adding, modifying and removing the default-network annotation on existing pods": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: Default network multus annotation when added with static IP and MAC to a pod belonging to primary UDN should create the pod with the specified static IP and MAC address": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: Localnet using ClusterUserDefinedNetwork CR, pods in different namespaces, should communicate over localnet topology": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: Network Policies on a user defined primary network allow ingress traffic to one pod from a particular namespace in L2 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation: Network Policies on a user defined primary network allow ingress traffic to one pod from a particular namespace in L3 primary UDN": "[Disabled:Unimplemented]",

	"Network Segmentation: Network Policies on a user defined primary network pods within namespace should be isolated when deny policy is present in L2 dualstack primary UDN with custom network": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: Network Policies on a user defined primary network pods within namespace should be isolated when deny policy is present in L2 dualstack primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: Network Policies on a user defined primary network pods within namespace should be isolated when deny policy is present in L3 dualstack primary UDN": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: Preconfigured Layer2 UDN should respect network configuration Layer2 basic configuration": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: Preconfigured Layer2 UDN should respect network configuration Layer2 with custom subnets": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: Preconfigured Layer2 UDN should respect network configuration Layer2 with inverted gateway/management IPs": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: services on a user defined primary network should be reachable through their cluster IP, node port and load balancer L2 primary UDN with custom network, cluster-networked pods, NodePort service": "[Suite:openshift/conformance/parallel]",

	"Network Segmentation: services on a user defined primary network should be reachable through their cluster IP, node port and load balancer L2 primary UDN, cluster-networked pods, NodePort service": "[Disabled:Unimplemented]",

	"Network Segmentation: services on a user defined primary network should be reachable through their cluster IP, node port and load balancer L3 primary UDN, cluster-networked pods, NodePort service": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv4 address is updated when ETP=Local service with host network backend is configured makes sure that the flows are updated with new IP address (update kubelet first, the IP address later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv4 address is updated when ETP=Local service with host network backend is configured makes sure that the flows are updated with new IP address (update the IP address first, kubelet later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv4 address is updated when EgressIPs are configured makes sure that the EgressIP is still operational (update kubelet first, the IP address later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv4 address is updated when EgressIPs are configured makes sure that the EgressIP is still operational (update the IP address first, kubelet later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv4 address is updated when no EgressIPs are configured makes sure that the cluster is still operational (update kubelet first, the IP address later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv4 address is updated when no EgressIPs are configured makes sure that the cluster is still operational (update the IP address first, kubelet later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv6 address is updated when ETP=Local service with host network backend is configured makes sure that the flows are updated with new IP address (update kubelet first, the IP address later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv6 address is updated when ETP=Local service with host network backend is configured makes sure that the flows are updated with new IP address (update the IP address first, kubelet later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv6 address is updated when EgressIPs are configured makes sure that the EgressIP is still operational (update kubelet first, the IP address later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv6 address is updated when EgressIPs are configured makes sure that the EgressIP is still operational (update the IP address first, kubelet later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv6 address is updated when no EgressIPs are configured makes sure that the cluster is still operational (update kubelet first, the IP address later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when the node IPv6 address is updated when no EgressIPs are configured makes sure that the cluster is still operational (update the IP address first, kubelet later)": "[Disabled:Unimplemented]",

	"Node IP and MAC address migration when when MAC address changes when a nodeport service is configured Ensures flows are updated when MAC address changes": "[Disabled:Unimplemented]",

	"OVS CPU affinity pinning can be enabled on specific nodes by creating enable_dynamic_cpu_affinity file": "[Disabled:Unimplemented]",

	"Pod to external server PMTUD when a client ovnk pod targeting an external server is created when tests are run towards the agnhost echo server queries to the hostNetworked server pod on another node shall work for TCP": "[Disabled:Unimplemented]",

	"Pod to external server PMTUD when a client ovnk pod targeting an external server is created when tests are run towards the agnhost echo server queries to the hostNetworked server pod on another node shall work for UDP": "[Disabled:Unimplemented]",

	"Pod to pod TCP with low MTU when a client ovnk pod targeting an ovnk pod server(running on another node) with low mtu when MTU is lowered between the two nodes large queries to the server pod on another node shall work for TCP": "[Disabled:Unimplemented]",

	"Service Hairpin SNAT Should ensure service hairpin traffic is NOT SNATed to hairpin masquerade IP; GR LB": "[Disabled:Unimplemented]",

	"Service Hairpin SNAT Should ensure service hairpin traffic is SNATed to hairpin masquerade IP; Switch LB": "[Disabled:Unimplemented]",

	"Services All service features work when manually listening on a non-default address": "[Disabled:Unimplemented]",

	"Services Allow connection to an external IP using a source port that is equal to a node port": "[Disabled:Unimplemented]",

	"Services Creates a host-network service, and ensures that host-network pods can connect to it": "[Disabled:Unimplemented]",

	"Services Creates a service with session-affinity, and ensures it works after backend deletion": "[Disabled:Unimplemented]",

	"Services does not use host masquerade address as source IP address when communicating externally": "[Disabled:Unimplemented]",

	"Services of type NodePort should handle IP fragments": "[Disabled:Unimplemented]",

	"Services of type NodePort should listen on each host addresses": "[Disabled:Unimplemented]",

	"Services of type NodePort should work on secondary node interfaces for ETP=local and ETP=cluster when backend pods are also served by EgressIP": "[Disabled:Unimplemented]",

	"Services when a nodePort service targeting a pod with hostNetwork:false is created when tests are run towards the agnhost echo service queries to the nodePort service shall work for TCP": "[Disabled:Unimplemented]",

	"Services when a nodePort service targeting a pod with hostNetwork:false is created when tests are run towards the agnhost echo service queries to the nodePort service shall work for UDP": "[Disabled:Unimplemented]",

	"Services when a nodePort service targeting a pod with hostNetwork:true is created when tests are run towards the agnhost echo service queries to the nodePort service shall work for TCP": "[Disabled:Unimplemented]",

	"Services when a nodePort service targeting a pod with hostNetwork:true is created when tests are run towards the agnhost echo service queries to the nodePort service shall work for UDP": "[Disabled:Unimplemented]",

	"Status manager validation Should validate the egress firewall status when adding a new zone": "[Disabled:Unimplemented]",

	"Status manager validation Should validate the egress firewall status when adding an unknown zone": "[Disabled:Unimplemented]",

	"Unidling Should generate a NeedPods event for traffic destined to idled services": "[Disabled:Unimplemented]",

	"Unidling With annotated service Should connect to an unidled backend at the first attempt": "[Disabled:Unimplemented]",

	"Unidling With annotated service Should generate a NeedPods event for traffic destined to idled services": "[Disabled:Unimplemented]",

	"Unidling With annotated service Should generate a NeedPods event when backends were added and then removed": "[Disabled:Unimplemented]",

	"Unidling With annotated service Should not generate a NeedPods event when has backend": "[Disabled:Unimplemented]",

	"Unidling With annotated service Should not generate a NeedPods event when removing the annotation": "[Disabled:Unimplemented]",

	"Unidling With non annotated service Should generate a NeedPods event when adding the annotation": "[Disabled:Unimplemented]",

	"Unidling With non annotated service Should not generate a NeedPods event for traffic destined to idled services": "[Disabled:Unimplemented]",

	"Unidling With non annotated service Should not generate a NeedPods event when backends were added and then removed": "[Disabled:Unimplemented]",

	"Unidling With non annotated service Should not generate a NeedPods event when has backend": "[Disabled:Unimplemented]",

	"blocking ICMP needs frag when a client VM pod with 1500 MTU targets a host networked pod should be able to send large TCP packet and not get a route cache entry": "[Disabled:Unimplemented]",

	"blocking ICMP needs frag when a client host networked pod with targets a proxy node nodeport service with ovnk networked backend should be able to send large UDP packet and not get a route cache entry": "[Disabled:Unimplemented]",

	"blocking ICMP needs frag when an ovnk pod targets a host networked pod with large UDP should be able to send large UDP packet and not get a route cache entry": "[Disabled:Unimplemented]",

	"e2e EgressQoS validation Should deny resources with bad values": "[Disabled:Unimplemented]",

	"e2e EgressQoS validation Should validate correct DSCP value on EgressQoS resource changes ipv4 pod after resource": "[Disabled:Unimplemented]",

	"e2e EgressQoS validation Should validate correct DSCP value on EgressQoS resource changes ipv4 pod before resource": "[Disabled:Unimplemented]",

	"e2e EgressQoS validation Should validate correct DSCP value on EgressQoS resource changes ipv6 pod after resource": "[Disabled:Unimplemented]",

	"e2e EgressQoS validation Should validate correct DSCP value on EgressQoS resource changes ipv6 pod before resource": "[Disabled:Unimplemented]",

	"e2e EgressQoS validation Should validate correct DSCP value on pod labels changes ipv4 pod": "[Disabled:Unimplemented]",

	"e2e EgressQoS validation Should validate correct DSCP value on pod labels changes ipv6 pod": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Limits egress traffic targeting a pod by protocol and port through a NetworkQoS spec ipv4": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Limits egress traffic targeting a pod by protocol and port through a NetworkQoS spec ipv6": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Limits egress traffic targeting an individual pod by protocol through a NetworkQoS spec ipv4": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Limits egress traffic targeting an individual pod by protocol through a NetworkQoS spec ipv6": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Limits egress traffic to all target pods below the specified rate in NetworkQoS spec ipv4": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Limits egress traffic to all target pods below the specified rate in NetworkQoS spec ipv6": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Should have correct DSCP value for host network traffic when NetworkQoS is applied ipv4": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Should have correct DSCP value for host network traffic when NetworkQoS is applied ipv6": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Should have correct DSCP value for overlay traffic when NetworkQoS is applied ipv4": "[Disabled:Unimplemented]",

	"e2e NetworkQoS validation Should have correct DSCP value for overlay traffic when NetworkQoS is applied ipv6": "[Disabled:Unimplemented]",

	"e2e br-int flow monitoring export validation Should validate flow data of br-int is sent to an external gateway with netflow v5": "[Disabled:Unimplemented]",

	"e2e br-int flow monitoring export validation Should validate flow data of br-int is sent to an external gateway with sflow": "[Disabled:Unimplemented]",

	"e2e control plane should provide Internet connection continuously when all ovnkube-control-plane pods are killed": "[Disabled:Unimplemented]",

	"e2e control plane should provide Internet connection continuously when all pods are killed on node running master instance of ovnkube-control-plane": "[Disabled:Unimplemented]",

	"e2e control plane should provide Internet connection continuously when ovnkube-node pod is killed": "[Disabled:Unimplemented]",

	"e2e control plane should provide Internet connection continuously when pod running master instance of ovnkube-control-plane is killed": "[Disabled:Unimplemented]",

	"e2e control plane should provide connection to external host by DNS name from a pod": "[Disabled:Unimplemented]",

	"e2e control plane test node readiness according to its defaults interface MTU size should get node not ready with a too small MTU": "[Disabled:Unimplemented]",

	"e2e control plane test node readiness according to its defaults interface MTU size should get node ready with a big enough MTU": "[Disabled:Unimplemented]",

	"e2e delete databases Should validate connectivity before and after deleting all the db-pods at once in HA mode": "[Disabled:Unimplemented]",

	"e2e delete databases Should validate connectivity before and after deleting all the db-pods at once in Non-HA mode": "[Disabled:Unimplemented]",

	"e2e delete databases recovering from deleting db files while maintaining connectivity when deleting both db files on ovnkube-db-0": "[Disabled:Unimplemented]",

	"e2e delete databases recovering from deleting db files while maintaining connectivity when deleting both db files on ovnkube-db-1": "[Disabled:Unimplemented]",

	"e2e delete databases recovering from deleting db files while maintaining connectivity when deleting both db files on ovnkube-db-2": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network Should re-assign egress IPs when node readiness / reachability goes down/up": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network Should validate egress IP logic when one pod is managed by more than one egressIP object": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network Should validate the egress IP SNAT functionality for stateful-sets": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network Should validate the egress IP functionality against remote hosts with egress firewall applied": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [OVN network] Should validate the egress IP SNAT functionality against host-networked pods": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding GRCP health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding Legacy health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes with egress-assignable label": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [OVN network] multiple namespaces sharing a role primary network": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [OVN network] multiple namespaces with different primary networks L2 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [OVN network] multiple namespaces with different primary networks L3 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [secondary-host-eip] Multiple EgressIP objects and their Egress IP hosted on the same interface": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv4": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 compressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 uncompressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [secondary-host-eip] Using different methods to disable a node or pod availability for egress": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network [secondary-host-eip] uses VRF routing table if EIP assigned interface is VRF slave": "[Disabled:Unimplemented]",

	"e2e egress IP validation Cluster Default Network of replies to egress IP packets that require fragmentation [LGW][IPv4]": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary Should re-assign egress IPs when node readiness / reachability goes down/up": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary Should validate egress IP logic when one pod is managed by more than one egressIP object": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary Should validate the egress IP SNAT functionality for stateful-sets": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary Should validate the egress IP functionality against remote hosts with egress firewall applied": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [OVN network] Should validate the egress IP SNAT functionality against host-networked pods": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding GRCP health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding Legacy health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes with egress-assignable label": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [OVN network] multiple namespaces sharing a role primary network": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [OVN network] multiple namespaces with different primary networks L2 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [OVN network] multiple namespaces with different primary networks L3 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [secondary-host-eip] Multiple EgressIP objects and their Egress IP hosted on the same interface": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv4": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 compressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 uncompressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary [secondary-host-eip] uses VRF routing table if EIP assigned interface is VRF slave": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L2 role primary of replies to egress IP packets that require fragmentation [LGW][IPv4]": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary Should re-assign egress IPs when node readiness / reachability goes down/up": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary Should validate egress IP logic when one pod is managed by more than one egressIP object": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary Should validate the egress IP SNAT functionality for stateful-sets": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary Should validate the egress IP functionality against remote hosts with egress firewall applied": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [OVN network] Should validate the egress IP SNAT functionality against host-networked pods": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding GRCP health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding Legacy health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes with egress-assignable label": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [OVN network] multiple namespaces sharing a role primary network": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [OVN network] multiple namespaces with different primary networks L2 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [OVN network] multiple namespaces with different primary networks L3 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [secondary-host-eip] Multiple EgressIP objects and their Egress IP hosted on the same interface": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv4": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 compressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 uncompressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary [secondary-host-eip] uses VRF routing table if EIP assigned interface is VRF slave": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv4 L3 role primary of replies to egress IP packets that require fragmentation [LGW][IPv4]": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary Should re-assign egress IPs when node readiness / reachability goes down/up": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary Should validate egress IP logic when one pod is managed by more than one egressIP object": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary Should validate the egress IP SNAT functionality for stateful-sets": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary Should validate the egress IP functionality against remote hosts with egress firewall applied": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [OVN network] Should validate the egress IP SNAT functionality against host-networked pods": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding GRCP health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding Legacy health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes with egress-assignable label": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [OVN network] multiple namespaces sharing a role primary network": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [OVN network] multiple namespaces with different primary networks L2 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [OVN network] multiple namespaces with different primary networks L3 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [secondary-host-eip] Multiple EgressIP objects and their Egress IP hosted on the same interface": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv4": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 compressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 uncompressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary [secondary-host-eip] uses VRF routing table if EIP assigned interface is VRF slave": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L2 role primary of replies to egress IP packets that require fragmentation [LGW][IPv4]": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary Should re-assign egress IPs when node readiness / reachability goes down/up": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary Should validate egress IP logic when one pod is managed by more than one egressIP object": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary Should validate the egress IP SNAT functionality for stateful-sets": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary Should validate the egress IP functionality against remote hosts with egress firewall applied": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [OVN network] Should validate the egress IP SNAT functionality against host-networked pods": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding GRCP health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes impeding Legacy health check": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [OVN network] Using different methods to disable a node's availability for egress Should validate the egress IP functionality against remote hosts disabling egress nodes with egress-assignable label": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [OVN network] multiple namespaces sharing a role primary network": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [OVN network] multiple namespaces with different primary networks L2 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [OVN network] multiple namespaces with different primary networks L3 Primary UDN": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [secondary-host-eip] Multiple EgressIP objects and their Egress IP hosted on the same interface": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv4": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 compressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress IPv6 uncompressed": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [secondary-host-eip] Using different methods to disable a node or pod availability for egress": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary [secondary-host-eip] uses VRF routing table if EIP assigned interface is VRF slave": "[Disabled:Unimplemented]",

	"e2e egress IP validation Network Segmentation: IPv6 L3 role primary of replies to egress IP packets that require fragmentation [LGW][IPv4]": "[Disabled:Unimplemented]",

	"e2e egress firewall policy validation with DNS name resolver Should validate that egressfirewall policy functionality for allowed DNS name": "[Disabled:Unimplemented]",

	"e2e egress firewall policy validation with external containers Should validate that egressfirewall supports DNS name in caps": "[Disabled:Unimplemented]",

	"e2e egress firewall policy validation with external containers Should validate the egress firewall allows inbound connections": "[Disabled:Unimplemented]",

	"e2e egress firewall policy validation with external containers Should validate the egress firewall doesn't affect internal connections": "[Disabled:Unimplemented]",

	"e2e egress firewall policy validation with external containers Should validate the egress firewall policy functionality for allowed CIDR and port": "[Disabled:Unimplemented]",

	"e2e egress firewall policy validation with external containers Should validate the egress firewall policy functionality for allowed IP": "[Disabled:Unimplemented]",

	"e2e ingress to host-networked pods traffic validation Validating ingress traffic to Host Networked pods with externalTrafficPolicy=local Should be allowed to node local host-networked endpoints by nodeport services": "[Disabled:Unimplemented]",

	"e2e ingress traffic validation Validating ingress traffic Should be allowed by externalip services": "[Disabled:Unimplemented]",

	"e2e ingress traffic validation Validating ingress traffic Should be allowed by nodeport services after upgrade to DualStack": "[Disabled:Unimplemented]",

	"e2e ingress traffic validation Validating ingress traffic Should be allowed by nodeport services": "[Disabled:Unimplemented]",

	"e2e ingress traffic validation Validating ingress traffic Should be allowed to node local cluster-networked endpoints by nodeport services with externalTrafficPolicy=local": "[Disabled:Unimplemented]",

	"e2e ingress traffic validation Validating ingress traffic to manually added node IPs Should be allowed by externalip services to a new node ip": "[Disabled:Unimplemented]",

	"e2e network policy hairpinning validation Should validate the hairpinned traffic is always allowed": "[Suite:openshift/conformance/parallel]",

	"test e2e inter-node connectivity between worker nodes Should validate connectivity within a namespace of pods on separate nodes": "[Disabled:Unimplemented]",

	"test e2e pod connectivity to host addresses Should validate connectivity from a pod to a non-node host address on same node": "[Disabled:Unimplemented]",
}

func init() {
	ginkgo.GetSuite().SetAnnotateFn(func(name string, node types.TestSpec) {
		if newLabels, ok := AppendedAnnotations[name]; ok {
			node.AppendText(newLabels)
		} else {
			panic(fmt.Sprintf("unable to find test %s", name))
		}
	})
}
