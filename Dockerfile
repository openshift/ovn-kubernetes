#
# This is the OpenShift ovn overlay network image.
# it provides an overlay network using ovs/ovn/ovn-kube
#
# The standard name for this image is ovn-kube

# Notes:
# This is for a build where the ovn-kubernetes utilities
# are built in this Dockerfile and included in the image (instead of the rpm)
#

FROM registry.ci.openshift.org/ocp/builder:rhel-8-golang-1.15-openshift-4.8 AS builder

WORKDIR /go/src/github.com/openshift/ovn-kubernetes
COPY . .

# build the binaries
RUN cd go-controller; CGO_ENABLED=0 make
RUN cd go-controller; CGO_ENABLED=0 make windows

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
ARG ovnver=20.12.0-25.el8fdp

#https://bugzilla.redhat.com/show_bug.cgi?id=1945415 - ARP lflow optimization
#COPY ovn2.13-20.12.0-99.el8fdp.x86_64.rpm ovn2.13-central-20.12.0-99.el8fdp.x86_64.rpm ovn2.13-host-20.12.0-99.el8fdp.x86_64.rpm ovn2.13-vtep-20.12.0-99.el8fdp.x86_64.rpm /root
# fix for ovn-installed plus above
COPY ovn2.13-20.12.0-117.el8fdp.x86_64.rpm ovn2.13-central-20.12.0-117.el8fdp.x86_64.rpm ovn2.13-host-20.12.0-117.el8fdp.x86_64.rpm ovn2.13-vtep-20.12.0-117.el8fdp.x86_64.rpm /root


# https://bugzilla.redhat.com/show_bug.cgi?id=1943631 - leadership transfer before snapshotting, and Anton's patch to limit time ovsdb processes db requests to % of election timer
# http://brew-task-repos.usersys.redhat.com/repos/scratch/imaximet/openvswitch2.15/2.15.0/2.bz1943631.2.3.el8fdp/x86_64/
# COPY openvswitch2.15-devel-2.15.0-4.el8fdp.x86_64.rpm python3-openvswitch2.15-2.15.0-4.el8fdp.x86_64.rpm openvswitch2.15-ipsec-2.15.0-4.el8fdp.x86_64.rpm /root
COPY openvswitch2.15-2.15.0-2.bz1943631.2.3.el8fdp.x86_64.rpm openvswitch2.15-devel-2.15.0-2.bz1943631.2.3.el8fdp.x86_64.rpm python3-openvswitch2.15-2.15.0-2.bz1943631.2.3.el8fdp.x86_64.rpm openvswitch2.15-ipsec-2.15.0-2.bz1943631.2.3.el8fdp.x86_64.rpm /root



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
	rpm -Uhv --force --nodeps /root/ovn2.13*.rpm && \
	rpm -Uhv --force --nodeps /root/openvswitch2.15*.rpm && \
	rpm -Uhv --force --nodeps /root/python3-openvswitch2.15*.rpm && \
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

