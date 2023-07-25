# URGENT! ART metadata configuration has a different number of FROMs
# than this Dockerfile. ART will be unable to build your component or
# reconcile this Dockerfile until that disparity is addressed.
#
# This is the OpenShift ovn overlay network image.
# it provides an overlay network using ovs/ovn/ovn-kube
#
# The standard name for this image is ovn-kube

# Notes:
# This is for a build where the ovn-kubernetes utilities
# are built in this Dockerfile and included in the image (instead of the rpm)
#

# Build RHEL-8 binaries
FROM registry.ci.openshift.org/ocp/builder:rhel-8-golang-1.16-openshift-4.8 AS builder
WORKDIR /go/src/github.com/openshift/ovn-kubernetes
COPY . .
RUN cd go-controller; CGO_ENABLED=1 make
RUN cd go-controller; CGO_ENABLED=1 make windows

# Build RHEL-7 binaries
FROM registry.ci.openshift.org/ocp/builder:rhel-7-golang-1.16-openshift-4.8 AS rhel7
WORKDIR /go/src/github.com/openshift/ovn-kubernetes
COPY . .
RUN cd go-controller; CGO_ENABLED=1 make

FROM registry.ci.openshift.org/ocp/4.8:cli AS cli

FROM registry.ci.openshift.org/ocp/4.8:base

USER root

ENV PYTHONDONTWRITEBYTECODE yes

# install needed rpms - openvswitch must be 2.10.4 or higher
# install selinux-policy first to avoid a race
RUN yum install -y  \
	selinux-policy && \
	yum clean all

ARG ovsver=2.15.0-9.el8fdp
ARG ovnver=20.12.0-196.el8fdp

RUN INSTALL_PKGS=" \
	openssl python3-pyOpenSSL firewalld-filesystem \
	libpcap iproute iproute-tc strace \
	containernetworking-plugins \
	tcpdump iputils \
	libreswan \
	ethtool conntrack-tools \
	" && \
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False $INSTALL_PKGS && \
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False "openvswitch2.15 = $ovsver" "openvswitch2.15-devel = $ovsver" "python3-openvswitch2.15 = $ovsver" "openvswitch2.15-ipsec = $ovsver" && \
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False "ovn2.13 = $ovnver" "ovn2.13-central = $ovnver" "ovn2.13-host = $ovnver" "ovn2.13-vtep = $ovnver" && \
	yum clean all && rm -rf /var/cache/*

RUN mkdir -p /var/run/openvswitch && \
    mkdir -p /var/run/ovn && \
    mkdir -p /etc/cni/net.d && \
    mkdir -p /opt/cni/bin && \
    mkdir -p /usr/libexec/cni/ && \
    mkdir -p /root/windows/

COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovnkube /usr/bin/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovn-kube-util /usr/bin/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovn-k8s-cni-overlay /usr/libexec/cni/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/windows/hybrid-overlay-node.exe /root/windows/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovndbchecker /usr/bin/
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovnkube-trace /usr/bin/

# Copy RHEL-8 and RHEL-7 shim binaries where the CNO's ovnkube-node container startup script can find them
RUN mkdir -p /usr/libexec/cni/rhel8
COPY --from=builder /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovn-k8s-cni-overlay /usr/libexec/cni/rhel8/
RUN mkdir -p /usr/libexec/cni/rhel7
COPY --from=rhel7 /go/src/github.com/openshift/ovn-kubernetes/go-controller/_output/go/bin/ovn-k8s-cni-overlay /usr/libexec/cni/rhel7/

COPY --from=cli /usr/bin/oc /usr/bin/
RUN ln -s /usr/bin/oc /usr/bin/kubectl
RUN stat /usr/bin/oc

# copy git commit number into image
COPY .git/HEAD /root/.git/HEAD
COPY .git/refs/heads/ /root/.git/refs/heads/

# ovnkube.sh is the entry point. This script examines environment
# variables to direct operation and configure ovn
COPY dist/images/ovnkube.sh /root/

# iptables wrappers
COPY ./dist/images/iptables-scripts/iptables /usr/sbin/
COPY ./dist/images/iptables-scripts/iptables-save /usr/sbin/
COPY ./dist/images/iptables-scripts/iptables-restore /usr/sbin/
COPY ./dist/images/iptables-scripts/ip6tables /usr/sbin/
COPY ./dist/images/iptables-scripts/ip6tables-save /usr/sbin/
COPY ./dist/images/iptables-scripts/ip6tables-restore /usr/sbin/
COPY ./dist/images/iptables-scripts/iptables /usr/sbin/

LABEL io.k8s.display-name="ovn kubernetes" \
      io.k8s.description="This is a component of OpenShift Container Platform that provides an overlay network using ovn." \
      summary="This is a component of OpenShift Container Platform that provides an overlay network using ovn." \
      io.openshift.tags="openshift" \
      maintainer="Tim Rozet <trozet@redhat.com>"

WORKDIR /root
ENTRYPOINT /root/ovnkube.sh

