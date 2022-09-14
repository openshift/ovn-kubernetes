#!/bin/bash

echo "ref: $(git rev-parse  --symbolic-full-name HEAD)  commit: $(git rev-parse  HEAD)" > git_info

make -C ../../go-controller

echo -n "is all good?"
read

cp ../../go-controller/_output/go/bin/* .

docker build -t docker.io/navadiaev/ovn-daemonset-f:latest -f Dockerfile.fedora .

docker push navadiaev/ovn-daemonset-f:latest