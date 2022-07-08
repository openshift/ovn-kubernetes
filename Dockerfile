#
# This is the OpenShift ovn overlay network image.
# it provides an overlay network using ovs/ovn/ovn-kube
#
# The standard name for this image is ovn-kubernetes

FROM registry.ci.openshift.org/ocp/builder:rhel-8-golang-1.18-openshift-4.12 AS builder

WORKDIR /go/src/github.com/openshift/ovn-kubernetes
COPY . .

# build the binaries
RUN cd go-controller; CGO_ENABLED=0 make
RUN cd go-controller; CGO_ENABLED=0 make windows

FROM registry.ci.openshift.org/ocp/4.12:cli AS cli

FROM registry.ci.openshift.org/ocp/4.12:ovn-kubernetes-base

USER root

ENV PYTHONDONTWRITEBYTECODE yes

RUN INSTALL_PKGS=" \
	openssl python3-pyOpenSSL firewalld-filesystem \
	libpcap iproute iproute-tc strace \
	containernetworking-plugins \
	tcpdump iputils \
	libreswan \
	ethtool conntrack-tools \
	" && \
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False $INSTALL_PKGS && \
	export ovsver=$(cat /ovs-version) && \
	export ovnver=$(cat /ovn-version) && \
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False "openvswitch2.17 = $ovsver" "openvswitch2.17-devel = $ovsver" "python3-openvswitch2.17 = $ovsver" "openvswitch2.17-ipsec = $ovsver" && \
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False "ovn22.06 = $ovnver" "ovn22.06-central = $ovnver" "ovn22.06-host = $ovnver" "ovn22.06-vtep = $ovnver" && \
	yum clean all && rm -rf /var/cache/*

COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovnkube /usr/bin/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovn-kube-util /usr/bin/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovn-k8s-cni-overlay /usr/libexec/cni/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/windows/hybrid-overlay-node.exe /root/windows/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovndbchecker /usr/bin/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovnkube-trace /usr/bin/

COPY --from=cli /usr/bin/oc /usr/bin/
RUN ln -s /usr/bin/oc /usr/bin/kubectl
RUN stat /usr/bin/oc

LABEL io.k8s.display-name="ovn kubernetes" \
      io.k8s.description="This is a component of OpenShift Container Platform that provides an overlay network using ovn." \
      summary="This is a component of OpenShift Container Platform that provides an overlay network using ovn." \
      io.openshift.tags="openshift" \
      maintainer="Tim Rozet <trozet@redhat.com>"
