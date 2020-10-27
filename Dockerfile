#
# This is the OpenShift ovn overlay network image.
# it provides an overlay network using ovs/ovn/ovn-kube
#
# The standard name for this image is ovn-kube

# Notes:
# This is for a build where the ovn-kubernetes utilities
# are built in this Dockerfile and included in the image (instead of the rpm)
#

FROM registry.svc.ci.openshift.org/ocp/builder:rhel-8-golang-1.15-openshift-4.7 AS builder

WORKDIR /go/src/github.com/openshift/ovn-kubernetes
COPY . .

# build the binaries
RUN cd go-controller; CGO_ENABLED=0 make
RUN cd go-controller; CGO_ENABLED=0 make windows

FROM registry.svc.ci.openshift.org/ocp/4.7:cli AS cli

FROM registry.svc.ci.openshift.org/ocp/4.7:base

USER root

ENV PYTHONDONTWRITEBYTECODE yes

# install needed rpms - openvswitch must be 2.10.4 or higher
# install selinux-policy first to avoid a race
RUN yum install -y  \
	selinux-policy && \
	yum clean all

RUN INSTALL_PKGS=" \
	openssl firewalld-filesystem \
	libpcap iproute strace \
	containernetworking-plugins \
	tcpdump iputils \
	" && \
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False $INSTALL_PKGS && \
	#======== 4.6.0-0.nightly-2020-09-25-070943 Version ========
	# ovn2.13-20.06.2-11.el8fdp.x86_64
	# openvswitch2.13-2.13.0-57.el8fdp
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False "openvswitch2.13 == 2.13.0-57.el8fdp" "openvswitch2.13-devel == 2.13.0-57.el8fdp" && \
	yum install -y --setopt=tsflags=nodocs --setopt=skip_missing_names_on_install=False "ovn2.13 == 20.06.2-11.el8fdp" "ovn2.13-central == 20.06.2-11.el8fdp" "ovn2.13-host == 20.06.2-11.el8fdp" "ovn2.13-vtep == 20.06.2-11.el8fdp" && \
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
      maintainer="Phil Cameron <pcameron@redhat.com>"

WORKDIR /root
ENTRYPOINT /root/ovnkube.sh

