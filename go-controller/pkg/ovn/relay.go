package ovn

import (
	"fmt"
	"context"

	v1 "k8s.io/api/core/v1"
	appsv1 "k8s.io/api/apps/v1"
	clientsetscheme "k8s.io/client-go/kubernetes/scheme"
	kuberuntime "k8s.io/apimachinery/pkg/runtime"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	clientset "k8s.io/client-go/kubernetes"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/klog/v2"

	"github.com/ovn-org/ovn-kubernetes/go-controller/pkg/config"
	"github.com/pkg/errors"
)

func startRelays(client clientset.Interface) error {
	relaysYAML := fmt.Sprintf(relaysTemplate, config.OvnSouth.GetURL())
	relayDeployment := &appsv1.Deployment{}
	if err := kuberuntime.DecodeInto(clientsetscheme.Codecs.UniversalDecoder(), []byte(relaysYAML), relayDeployment); err != nil {
		return errors.Wrap(err, "failed to decode relays deployment YAML")
	}

	relayService := &v1.Service{}
	if err := kuberuntime.DecodeInto(clientsetscheme.Codecs.UniversalDecoder(), []byte(serviceYAML), relayService); err != nil {
		return errors.Wrap(err, "failed to decode relays service YAML")
	}

	klog.Infof("\n---\n%s\n---\n%s\n", serviceYAML, relaysYAML)

	dcClient := client.AppsV1().Deployments(config.Kubernetes.OVNConfigNamespace)
	_, err := dcClient.Get(context.TODO(), "ovnkube-sbdb-relay", metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return errors.Wrap(err, "failed to get relay deployment")
		}
		_, err = dcClient.Create(context.TODO(), relayDeployment, metav1.CreateOptions{})
		if err != nil {
			return errors.Wrap(err, "failed to create relay deployment")
		}
		klog.Infof("##### Created relay deployment")
	}

	servicesClient := client.CoreV1().Services(config.Kubernetes.OVNConfigNamespace)
	_, err = servicesClient.Get(context.TODO(), "ovnkube-sbdb-relay", metav1.GetOptions{})
	if err != nil {
		if !apierrors.IsNotFound(err) {
			return errors.Wrap(err, "failed to get relay service")
		}
		_, err = servicesClient.Create(context.TODO(), relayService, metav1.CreateOptions{})
		if err != nil {
			return errors.Wrap(err, "failed to create relay service")
		}
		klog.Infof("##### Created relay service")
	}

	return nil
}

const serviceYAML string = `
apiVersion: v1
kind: Service
metadata:
  name: ovnkube-sbdb-relay
  namespace: openshift-ovn-kubernetes
spec:
  selector:
    app: ovnkube-sbdb-relay
  ports:
  - name: south
    port: 9642
    protocol: TCP
    targetPort: 9642 
  sessionAffinity: None
  clusterIP: None
  type: ClusterIP
`

const relaysTemplate string = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ovnkube-sbdb-relay
  namespace: openshift-ovn-kubernetes
  annotations:
    kubernetes.io/description: |
      This daemonset launches the ovn-kubernetes OVN SBDB relay networking components.
spec:
  replicas: 3 
  selector:
    matchLabels:
      app: ovnkube-sbdb-relay
  updateStrategy:
    type: RollingUpdate
    rollingUpdate:
      maxUnavailable: 10%%
  template:
    metadata:
      annotations:
        target.workload.openshift.io/management: '{"effect": "PreferredDuringScheduling"}'
      labels:
        app: ovnkube-sbdb-relay
        component: network
        type: infra
        openshift.io/component: network
        kubernetes.io/os: "linux"
    spec:
      serviceAccountName: ovn-kubernetes-controller
      hostNetwork: true
      priorityClassName: "system-node-critical"
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - ovnkube-sbdb-relay
            topologyKey: "kubernetes.io/hostname"
      containers:
      - name: ovn-sbdb-relay
        #image: "{{.OvnImage}}"
        image: quay.io/mcambria/ovn-kubernetes-scaletest:2021-08-04
        command:
        - /bin/bash
        - -c
        - |
          set -e
          if [[ -f "/env/${K8S_NODE}" ]]; then
            set -o allexport
            source "/env/${K8S_NODE}"
            set +o allexport
          fi  
          
          echo "$(date -Iseconds) - starting ovsdb-server as ovn-sbdb-relay"
          echo "Starting on node $HOSTNAME"
          ovsdb-server -vconsole:info -vsyslog:err -vfile:info \
            --no-chdir \
            -p /ovn-cert/tls.key -c /ovn-cert/tls.crt -C /ovn-ca/ca-bundle.crt \
            --remote=db:OVN_Southbound,SB_Global,connections \
            --pidfile=/var/run/ovn/ovsdb-relay.pid \
            --unixctl=/var/run/ovn/ovnsb_relay_db.ctl \
            --log-file=/var/log/ovn/ovsdb-relay.log \
            relay:OVN_Southbound:%s
        env:
        - name: OVN_LOG_LEVEL
          value: info
        - name: K8S_NODE
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: K8S_NODE_IP
          valueFrom:
            fieldRef:
              fieldPath: status.hostIP
        volumeMounts:
        - mountPath: /etc/openvswitch/
          name: etc-openvswitch
        - mountPath: /etc/ovn/
          name: etc-openvswitch
        - mountPath: /var/lib/openvswitch/
          name: var-lib-openvswitch
        - mountPath: /run/openvswitch/
          name: run-openvswitch
        - mountPath: /run/ovn/
          name: run-ovn
        - mountPath: /env
          name: env-overrides
        - mountPath: /ovn-cert
          name: ovn-cert
        - mountPath: /ovn-ca
          name: ovn-ca
        - mountPath: /var/log/ovn
          name: node-log
        terminationMessagePolicy: FallbackToLogsOnError
        resources:
          requests:
            cpu: 10m
            memory: 300Mi
      nodeSelector:
        node-role.kubernetes.io/worker: ""
        beta.kubernetes.io/os: "linux"
      volumes:
      - name: var-lib-openvswitch
        hostPath:
          path: /var/lib/ovn/data
      - name: etc-openvswitch
        hostPath:
          path: /var/lib/ovn/etc
      - name: run-openvswitch
        hostPath:
          path: /var/run/openvswitch
      - name: run-ovn
        hostPath:
          path: /var/run/ovn
      - name: node-log
        hostPath: 
          path: /var/log/ovn
      - name: env-overrides
        configMap:
          name: env-overrides
          optional: true
      - name: ovn-ca
        configMap:
          name: ovn-ca
      - name: ovn-cert
        secret:
          secretName: ovn-cert
      tolerations:
      - operator: "Exists"
`
