#!/bin/bash

function watch_core_dns_ep () {
  set +ex
  local print_count=0
  local print_interval=30
  local watch_interval=5
  while true; do
    is_dns_up=$(kubectl get ep dns-default -n openshift-dns -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null)
    if [[ -n "${is_dns_up}" ]]; then
      break
    fi
    if [[ $(($print_count % $print_interval)) == 0 ]]; then
      echo "[$(date +%Y-%m-%dT%H:%M:%SZ)][watch_core_dns_ep] waiting for CoreDNS to start..."
    fi
    print_count=$(($print_count+$watch_interval))
    sleep $watch_interval
  done

  echo "[$(date +%Y-%m-%dT%H:%M:%SZ)][watch_core_dns_ep] CoreDNS is up, replacing inherited nameserver entry from host with CoreDNS service IP in /etc/resolv.conf"
  core_dns_svc_ip=$(kubectl get svc dns-default -n openshift-dns -o jsonpath='{.spec.clusterIP}' 2>/dev/null)

  sed -e "s/nameserver.*/nameserver $core_dns_svc_ip/g" /etc/resolv.conf > resolv.tmp
  cp -f resolv.tmp /etc/resolv.conf
  rm resolv.tmp

  # Perform DNS resolution against the DNS resolver first and /etc/hosts second
  sed -i 's/hosts:      files dns myhostname/hosts:      dns files myhostname/g' /etc/nsswitch.conf
}

