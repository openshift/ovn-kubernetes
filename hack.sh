#!/bin/bash

#
# easy hack image for ovnkube hacking
# to use this:
# export SERIAL=1
# ./local/hack.sh && podman push quay.io/casey_callendrello/casey-test:ovn"${SERIAL}" && (( SERIAL += 1 ))
set -ex

echo my test

serial=$(uuidgen)

cd go-controller
make
cd ../local
cp ../go-controller/_output/go/bin/* ./

buildah build-using-dockerfile -t "quay.io/aconstan/ovn-raft:${serial}" -f Dockerfile.hack .
buildah push "quay.io/aconstan/ovn-raft:${serial}"
