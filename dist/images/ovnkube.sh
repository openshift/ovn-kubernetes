#!/bin/bash
#set -euo pipefail

# Enable verbose shell output if OVNKUBE_SH_VERBOSE is set to 'true'
if [[ "${OVNKUBE_SH_VERBOSE:-}" == "true" ]]; then
  set -x
fi

# This script is the entrypoint to the image.
# Supports version 3 daemonsets
#    $1 is the daemon to start.
#        In version 3 each process has a separate container. Some daemons start
#        more than 1 process. Also, where possible, output is to stdout and
#        The script waits for prerquisite deamons to come up first.
# Commands ($1 values)
#    ovs-server     Runs the ovs daemons - ovsdb-server and ovs-switchd (v3)
#    run-ovn-northd Runs ovn-northd as a process does not run nb_ovsdb or sb_ovsdb (v3)
#    nb-ovsdb       Runs nb_ovsdb as a process (no detach or monitor) (v3)
#    sb-ovsdb       Runs sb_ovsdb as a process (no detach or monitor) (v3)
#    ovn-master     Runs ovnkube in master mode (v3)
#    ovn-controller Runs ovn controller (v3)
#    ovn-node       Runs ovnkube in node mode (v3)
#    cleanup-ovn-node   Runs ovnkube to cleanup the node (v3)
#    cleanup-ovs-server Cleanup ovs-server (v3)
#    run-nbctld     Runs ovn-nbctl in the daemon mode (v3)
#    display        Displays log files
#    display_env    Displays environment variables
#    ovn_debug      Displays ovn/ovs configuration and flows

# NOTE: The script/image must be compatible with the daemonset.
# This script supports version 3 daemonsets
#      When called, it starts all needed daemons.

# ====================
# Environment variables are used to customize operation
# K8S_APISERVER - hostname:port (URL)of the real apiserver, not the service address - v3
# OVN_NET_CIDR - the network cidr - v3
# OVN_SVC_CIDR - the cluster-service-cidr - v3
# OVN_KUBERNETES_NAMESPACE - k8s namespace - v3
# K8S_NODE - hostname of the node - v3
#
# OVN_DAEMONSET_VERSION - version match daemonset and image - v3
# K8S_TOKEN - the apiserver token. Automatically detected when running in a pod - v3
# K8S_CACERT - the apiserver CA. Automatically detected when running in a pod - v3
# OVN_CONTROLLER_OPTS - the options for ovn-ctl
# OVN_NORTHD_OPTS - the options for the ovn northbound db
# OVN_GATEWAY_MODE - the gateway mode (shared or local) - v3
# OVN_GATEWAY_OPTS - the options for the ovn gateway
# OVNKUBE_LOGLEVEL - log level for ovnkube (0..5, default 4) - v3
# OVN_LOG_NORTHD - log level (ovn-ctl default: -vconsole:emer -vsyslog:err -vfile:info) - v3
# OVN_LOG_NB - log level (ovn-ctl default: -vconsole:off -vfile:info) - v3
# OVN_LOG_SB - log level (ovn-ctl default: -vconsole:off -vfile:info) - v3
# OVN_LOG_CONTROLLER - log level (ovn-ctl default: -vconsole:off -vfile:info) - v3
# OVN_LOG_NBCTLD - log file (ovn-nbctl daemon mode default: /var/log/openvswitch/ovn-nbctl.log)
# OVN_NB_PORT - ovn north db port (default 6641)
# OVN_SB_PORT - ovn south db port (default 6642)

# The argument to the command is the operation to be performed
# ovn-master ovn-controller ovn-node display display_env ovn_debug
# a cmd must be provided, there is no default
cmd=${1:-""}

# ovn daemon log levels
ovn_log_northd=${OVN_LOG_NORTHD:-"-vconsole:info"}
ovn_log_nb=${OVN_LOG_NB:-"-vconsole:info"}
ovn_log_sb=${OVN_LOG_SB:-"-vconsole:info"}
ovn_log_controller=${OVN_LOG_CONTROLLER:-"-vconsole:info"}

ovnkubelogdir=/var/log/ovn-kubernetes

# ovnkube.sh version (update when API between daemonset and script changes - v.x.y)
ovnkube_version="3"

# The daemonset version must be compatible with this script.
# The default when OVN_DAEMONSET_VERSION is not set is version 3
ovn_daemonset_version=${OVN_DAEMONSET_VERSION:-"3"}

# hostname is the host's hostname when using host networking,
# This is useful on the master node
# otherwise it is the container ID (useful for debugging).
ovn_pod_host=$(hostname)

# The ovs user id, by default it is going to be root:root
ovs_user_id=${OVS_USER_ID:-""}

# ovs options
ovs_options=${OVS_OPTIONS:-""}

if [[ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]]
then
  k8s_token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
else
  k8s_token=${K8S_TOKEN}
fi

K8S_CACERT=${K8S_CACERT:-/var/run/secrets/kubernetes.io/serviceaccount/ca.crt}

# ovn-northd - /etc/sysconfig/ovn-northd
ovn_northd_opts=${OVN_NORTHD_OPTS:-""}

# ovn-controller
ovn_controller_opts=${OVN_CONTROLLER_OPTS:-""}

# set the log level for ovnkube
ovnkube_loglevel=${OVNKUBE_LOGLEVEL:-4}

# by default it is going to be a shared gateway mode, however this can be overridden to any of the other
# two gateway modes that we support using `images/daemonset.sh` tool
ovn_gateway_mode=${OVN_GATEWAY_MODE:-"shared"}
ovn_gateway_opts=${OVN_GATEWAY_OPTS:-""}

net_cidr=${OVN_NET_CIDR:-10.128.0.0/14/23}
svc_cidr=${OVN_SVC_CIDR:-172.30.0.0/16}
mtu=${OVN_MTU:-1400}

ovn_kubernetes_namespace=${OVN_KUBERNETES_NAMESPACE:-ovn-kubernetes}

# host on which ovnkube-db POD is running and this POD contains both
# OVN NB and SB DB running in their own container
ovn_db_host=""

# OVN_NB_PORT - ovn north db port (default 6641)
ovn_nb_port=${OVN_NB_PORT:-6641}
# OVN_SB_PORT - ovn south db port (default 6642)
ovn_sb_port=${OVN_SB_PORT:-6642}

ovn_hybrid_overlay_enable=${OVN_HYBRID_OVERLAY_ENABLE:-}
ovn_hybrid_overlay_net_cidr=${OVN_HYBRID_OVERLAY_NET_CIDR:-}

# Determine the ovn rundir.
if [[ -f /usr/bin/ovn-appctl ]] ; then
	# ovn-appctl is present. Use new ovn run dir path.
	OVN_RUNDIR=/var/run/ovn
	OVNCTL_PATH=/usr/share/ovn/scripts/ovn-ctl
	OVN_LOGDIR=/var/log/ovn
  OVN_ETCDIR=/etc/ovn
else
	# ovn-appctl is not present. Use openvswitch run dir path.
	OVN_RUNDIR=/var/run/openvswitch
	OVNCTL_PATH=/usr/share/openvswitch/scripts/ovn-ctl
	OVN_LOGDIR=/var/log/openvswitch
  OVN_ETCDIR=/etc/openvswitch
fi

OVS_RUNDIR=/var/run/openvswitch
OVS_LOGDIR=/var/log/openvswitch

ovn_log_nbctld=${OVN_LOG_NBCTLD:-"${OVN_LOGDIR}/ovn-nbctl.log"}

# =========================================

setup_ovs_permissions () {
  if [ ${ovs_user_id:-XX} != "XX" ]; then
      chown -R ${ovs_user_id} /etc/openvswitch
      chown -R ${ovs_user_id} ${OVS_RUNDIR}
      chown -R ${ovs_user_id} ${OVS_LOGDIR}
      chown -R ${ovs_user_id} ${OVN_ETCDIR}
      chown -R ${ovs_user_id} ${OVN_RUNDIR}
      chown -R ${ovs_user_id} ${OVN_LOGDIR}
  fi
}

run_as_ovs_user_if_needed () {
  setup_ovs_permissions

  if [ ${ovs_user_id:-XX} != "XX" ]; then
      local uid=$(id -u "${ovs_user_id%:*}")
      local gid=$(id -g "${ovs_user_id%:*}")
      local groups=$(id -G "${ovs_user_id%:*}" | tr ' ' ',')

      setpriv --reuid $uid --regid $gid --groups $groups "$@"
      echo "run as: setpriv --reuid $uid --regid $gid --groups $groups $@"
  else
      "$@"
      echo "run as: $@"
  fi
}

# wait_for_event [attempts=<num>] function_to_call [arguments_to_function]
#
# Processes running inside the container should immediately start, so we
# shouldn't be making 80 attempts (default value). The "attempts=<num>"
# argument will help us in configuring that value.
wait_for_event () {
  retries=0
  sleeper=1
  attempts=80
  if [[ $1 =~ ^attempts= ]]; then
    eval $1
    shift
  fi
  while true; do
    $1 $2
    if [[ $? != 0 ]] ; then
      (( retries += 1 ))
      if [[ "${retries}" -gt ${attempts} ]]; then
        echo "error: $1 $2 did not come up, exiting"
        exit 1
      fi
      echo "info: Waiting for $1 $2 to come up, waiting ${sleeper}s ..."
      sleep ${sleeper}
      sleeper=5
    else
      if [[ "${retries}" != 0 ]]; then
        echo "$1 $2 came up in ${retries} ${sleeper} sec tries"
      fi
      break
    fi
  done

}

# OVN DBs must be up and initialized before ovn-master and ovn-node PODs can come up
# This waits for ovnkube-db POD to come up
ready_to_start_node () {

  # See if ep is available ...
  ovn_db_host=$(kubectl --server=${K8S_APISERVER} --token=${k8s_token} --certificate-authority=${K8S_CACERT} \
    get ep -n ${ovn_kubernetes_namespace} ovnkube-db 2>/dev/null | grep ${ovn_sb_port} | sed 's/:/ /' | awk '/ovnkube-db/{ print $2 }')
  if [[ ${ovn_db_host} == "" ]] ; then
      return 1
  fi
  get_ovn_db_vars
  ovn-nbctl --db=${ovn_nbdb_test} show > /dev/null 2>&1
  if [[ $? != 0 ]] ; then
      return 1
  fi
  return 0
}
# wait_for_event ready_to_start_node


# check that daemonset version is among expected versions
check_ovn_daemonset_version () {
  ok=$1
  for v in ${ok} ; do
    if [[ $v == ${ovn_daemonset_version} ]] ; then
      return 0
    fi
  done
  echo "VERSION MISMATCH expect ${ok}, daemonset is version ${ovn_daemonset_version}"
  exit 1
}

get_ovn_db_vars () {
  ovn_nbdb=tcp://${ovn_db_host}:${ovn_nb_port}
  ovn_sbdb=tcp://${ovn_db_host}:${ovn_sb_port}
  ovn_nbdb_test=$(echo ${ovn_nbdb} | sed 's;//;;')
}

# OVS must be up before OVN comes up.
# This checks if OVS is up and running
ovs_ready () {
  for daemon in `echo ovsdb-server ovs-vswitchd` ; do
    pidfile=${OVS_RUNDIR}/${daemon}.pid
    if [[ -f ${pidfile} ]] ; then
      check_health $daemon $(cat $pidfile)
      if [[ $? == 0 ]] ; then
        continue
      fi
    fi
    return 1
  done
  return 0
}


# Verify that the process is running either by checking for the PID in `ps` output
# or by using `ovs-appctl` utility for the processes that support it.
# $1 is the name of the process
process_ready () {
  case ${1} in
    "ovsdb-server"|"ovs-vswitchd")
    pidfile=${OVS_RUNDIR}/${1}.pid
    ;;
    *)
    pidfile=${OVN_RUNDIR}/${1}.pid
    ;;
  esac

  if [[ -f ${pidfile} ]] ; then
    check_health $1 $(cat $pidfile)
    if [[ $? == 0 ]] ; then
      return 0
    fi
  fi
  return 1
}


# continously checks if process is healthy. Exits if process terminates.
# $1 is the name of the process
# $2 is the pid of an another process to kill before exiting
process_healthy () {
  case ${1} in
    "ovsdb-server"|"ovs-vswitchd")
    pid=$(cat ${OVS_RUNDIR}/${1}.pid)
    ;;
    *)
    pid=$(cat ${OVN_RUNDIR}/${1}.pid)
    ;;
  esac

  while true; do
    check_health $1 ${pid}
    if [[ $? != 0 ]] ; then
      echo "=============== pid ${pid} terminated ========== "
      # kill the tail -f
      kill $2
      exit 6
    fi
    sleep 15
  done
}

# checks for the health of the process either using `ps` or `ovs-appctl`
# $1 is the name of the process
# $2 is the process pid
check_health () {
  ctl_file=""
  case ${1} in
    "ovnkube"|"ovnkube-master")
    ;;
    "ovnnb_db"|"ovnsb_db")
    ctl_file=${OVN_RUNDIR}/${1}.ctl
    ;;
    "ovn-northd"|"ovn-controller"|"ovsdb-server"|"ovs-vswitchd"|"ovn-nbctl")
    ctl_file=${OVN_RUNDIR}/${1}.${2}.ctl
    ;;
    *)
    echo "Unknown service ${1} specified. Exiting.. "
    exit 1
    ;;
  esac

  if [[ ${ctl_file} == "" ]] ; then
    # no control file, so just do the PID check
    pid=${2}
    pidTest=$(ps ax | awk '{ print $1 }' | grep "^${pid:-XX}$")
    if [[ ${pid:-XX} == ${pidTest} ]] ; then
      return 0
    fi
  else
    # use ovs-appctl to do the check
    ovs-appctl -t ${ctl_file} version &>/dev/null
    if [[ $? == 0 ]] ; then
        return 0
    fi
  fi

  return 1
}

display_file () {
    if [[ -f $3 ]]
    then
      echo "====================== $1 pid "
      cat $2
      echo "====================== $1 log "
      cat $3
      echo " "
    fi
}

# pid and log file for each container
display () {
  echo "==================== display for ${ovn_pod_host}  =================== "
  date
  display_file "nb-ovsdb" ${OVN_RUNDIR}/ovnnb_db.pid ${OVN_LOGDIR}/ovsdb-server-nb.log
  display_file "sb-ovsdb" ${OVN_RUNDIR}/ovnsb_db.pid ${OVN_LOGDIR}/ovsdb-server-sb.log
  display_file "run-ovn-northd" ${OVN_RUNDIR}/ovn-northd.pid ${OVN_LOGDIR}/ovn-northd.log
  display_file "ovn-master" ${OVN_RUNDIR}/ovnkube-master.pid ${ovnkubelogdir}/ovnkube-master.log
  display_file "ovs-vswitchd" ${OVS_RUNDIR}/ovs-vswitchd.pid ${OVS_LOGDIR}/ovs-vswitchd.log
  display_file "ovsdb-server" ${OVS_RUNDIR}/ovsdb-server.pid ${OVS_LOGDIR}/ovsdb-server.log
  display_file "ovn-controller" ${OVN_RUNDIR}/ovn-controller.pid ${OVN_LOGDIR}/ovn-controller.log
  display_file "ovnkube" ${OVN_RUNDIR}/ovnkube.pid ${ovnkubelogdir}/ovnkube.log
  display_file "run-nbctld" ${OVN_RUNDIR}/ovn-nbctl.pid ${OVN_LOGDIR}/ovn-nbctl.log
}

setup_cni () {
  cp -f /usr/libexec/cni/ovn-k8s-cni-overlay /opt/cni/bin/ovn-k8s-cni-overlay
}

display_version () {
  echo " =================== hostname: ${ovn_pod_host}"
  echo " =================== daemonset version ${ovn_daemonset_version}"
  if [[ -f /root/git_info ]]
  then
	disp_ver=$(cat /root/git_info)
	echo " =================== Image built from ovn-kubernetes ${disp_ver}"
	return
  fi
}

display_env () {
echo OVS_USER_ID ${ovs_user_id}
echo OVS_OPTIONS ${ovs_options}
echo OVN_NORTH ${ovn_nbdb}
echo OVN_NORTHD_OPTS ${ovn_northd_opts}
echo OVN_SOUTH ${ovn_sbdb}
echo OVN_CONTROLLER_OPTS ${ovn_controller_opts}
echo OVN_LOG_CONTROLLER ${ovn_log_controller}
echo OVN_GATEWAY_MODE ${ovn_gateway_mode}
echo OVN_GATEWAY_OPTS ${ovn_gateway_opts}
echo OVN_NET_CIDR ${net_cidr}
echo OVN_SVC_CIDR ${svc_cidr}
echo OVN_NB_PORT ${ovn_nb_port}
echo OVN_SB_PORT ${ovn_sb_port}
echo K8S_APISERVER ${K8S_APISERVER}
echo OVNKUBE_LOGLEVEL ${ovnkube_loglevel}
echo OVN_DAEMONSET_VERSION ${ovn_daemonset_version}
echo ovnkube.sh version ${ovnkube_version}
}

ovn_debug () {
  # get ovn_db_host
  ready_to_start_node
  echo "ovn_nbdb ${ovn_nbdb}   ovn_sbdb ${ovn_sbdb}"
  echo "ovn_nbdb_test ${ovn_nbdb_test}"

  # get ovs/ovn info from the node for debug purposes
  echo "=========== ovn_debug   hostname: ${ovn_pod_host} ============="
  echo "=========== ovn-nbctl show ============="
  echo "=========== ovn-nbctl --db=${ovn_nbdb_test} show ============="
  ovn-nbctl --db=${ovn_nbdb_test} show
  echo " "
  echo "=========== ovn-nbctl list ACL ============="
  ovn-nbctl --db=${ovn_nbdb_test} list ACL
  echo " "
  echo "=========== ovn-nbctl list address_set ============="
  ovn-nbctl --db=${ovn_nbdb_test} list address_set
  echo " "
  echo "=========== ovs-vsctl show ============="
  ovs-vsctl show
  echo " "
  echo "=========== ovs-ofctl -O OpenFlow13 dump-ports br-int ============="
  ovs-ofctl -O OpenFlow13 dump-ports br-int
  echo " "
  echo "=========== ovs-ofctl -O OpenFlow13 dump-ports-desc br-int ============="
  ovs-ofctl -O OpenFlow13 dump-ports-desc br-int
  echo " "
  echo "=========== ovs-ofctl dump-flows br-int ============="
  ovs-ofctl dump-flows br-int
  echo " "
  echo "=========== ovn-sbctl show ============="
  ovn_sbdb_test=$(echo ${ovn_sbdb} | sed 's;//;;')
  echo "=========== ovn-sbctl --db=${ovn_sbdb_test} show ============="
  ovn-sbctl --db=${ovn_sbdb_test} show
  echo " "
  echo "=========== ovn-sbctl --db=${ovn_sbdb_test} lflow-list ============="
  ovn-sbctl --db=${ovn_sbdb_test} lflow-list
  echo " "
  echo "=========== ovn-sbctl --db=${ovn_sbdb_test} list datapath ============="
  ovn-sbctl --db=${ovn_sbdb_test} list datapath
  echo " "
  echo "=========== ovn-sbctl --db=${ovn_sbdb_test} list port ============="
  ovn-sbctl --db=${ovn_sbdb_test} list port
}

ovs-server () {
  # start ovs ovsdb-server and ovs-vswitchd
  set -euo pipefail

  # if another process is listening on the cni-server socket, wait until it exits
  trap 'kill $(jobs -p); exit 0' TERM
  retries=0
  while true; do
    if /usr/share/openvswitch/scripts/ovs-ctl status &>/dev/null; then
      echo "warning: Another process is currently managing OVS, waiting 10s ..." 2>&1
      sleep 10 & wait
      (( retries += 1 ))
    else
      break
    fi
    if [[ "${retries}" -gt 60 ]]; then
      echo "error: Another process is currently managing OVS, exiting" 2>&1
      exit 1
    fi
  done
  rm -f ${OVS_RUNDIR}/ovs-vswitchd.pid
  rm -f ${OVS_RUNDIR}/ovsdb-server.pid

  # launch OVS
  function quit {
      /usr/share/openvswitch/scripts/ovs-ctl stop
      exit 1
  }
  trap quit SIGTERM

  setup_ovs_permissions

  USER_ARGS=""
  if [ ${ovs_user_id:-XX} != "XX" ]; then
      USER_ARGS="--ovs-user=${ovs_user_id}"
  fi

  /usr/share/openvswitch/scripts/ovs-ctl start --no-ovs-vswitchd \
    --system-id=random ${ovs_options} ${USER_ARGS} "$@"

  # Restrict the number of pthreads ovs-vswitchd creates to reduce the
  # amount of RSS it uses on hosts with many cores
  # https://bugzilla.redhat.com/show_bug.cgi?id=1571379
  # https://bugzilla.redhat.com/show_bug.cgi?id=1572797
  if [[ `nproc` -gt 12 ]]; then
      ovs-vsctl --no-wait set Open_vSwitch . other_config:n-revalidator-threads=4
      ovs-vsctl --no-wait set Open_vSwitch . other_config:n-handler-threads=10
  fi
  /usr/share/openvswitch/scripts/ovs-ctl start --no-ovsdb-server \
    --system-id=random ${ovs_options} ${USER_ARGS} "$@"

  # Ensure GENEVE's UDP port isn't firewalled
  /usr/share/openvswitch/scripts/ovs-ctl --protocol=udp --dport=6081 enable-protocol

  tail --follow=name ${OVS_LOGDIR}/ovs-vswitchd.log ${OVS_LOGDIR}/ovsdb-server.log &
  ovs_tail_pid=$!
  sleep 10
  while true; do
    if ! /usr/share/openvswitch/scripts/ovs-ctl status &>/dev/null; then
      echo "OVS seems to have crashed, exiting"
      kill ${ovs_tail_pid}
      quit
    fi
    sleep 15
  done
}

cleanup-ovs-server () {
  echo "=============== time: $(date +%d-%m-%H:%M:%S:%N) cleanup-ovs-server (wait for ovn-node to exit) ======="
  retries=0
  while [[ ${retries} -lt 80 ]]; do
    if [[ ! -e ${OVN_RUNDIR}/ovnkube.pid ]] ; then
      break
    fi
    echo "=============== time: $(date +%d-%m-%H:%M:%S:%N) cleanup-ovs-server ovn-node still running, wait) ======="
    sleep 1
    (( retries += 1 ))
  done
  echo "=============== time: $(date +%d-%m-%H:%M:%S:%N) cleanup-ovs-server (ovs-ctl stop) ======="
  /usr/share/openvswitch/scripts/ovs-ctl stop
}

# set the ovnkube_db endpoint for other pods to query the OVN DB IP
set_ovnkube_db_ep () {
  # create a new endpoint for the headless onvkube-db service without selectors
  # using the current host has the endpoint IP
  ovn_db_host=$(getent ahosts $(hostname) | head -1 | awk '{ print $1 }')
  kubectl --server=${K8S_APISERVER} --token=${k8s_token} --certificate-authority=${K8S_CACERT} apply -f - << EOF
apiVersion: v1
kind: Endpoints
metadata:
  name: ovnkube-db
  namespace: ${ovn_kubernetes_namespace}
subsets:
  - addresses:
      - ip: ${ovn_db_host}
    ports:
    - name: north
      port: ${ovn_nb_port}
      protocol: TCP
    - name: south
      port: ${ovn_sb_port}
      protocol: TCP
EOF
    if [[ $? != 0 ]] ; then
        echo "Failed to create endpoint with host ${ovn_db_host} for ovnkube-db service"
        exit 1
    fi
}

# v3 - run nb_ovsdb in a separate container
nb-ovsdb () {
  trap 'kill $(jobs -p); exit 0' TERM
  check_ovn_daemonset_version "3"
  rm -f ${OVN_RUNDIR}/ovnnb_db.pid

  # Make sure /var/lib/openvswitch exists
  mkdir -p /var/lib/openvswitch

  iptables-rules ${ovn_nb_port}

  echo "=============== run nb_ovsdb ========== MASTER ONLY"
  run_as_ovs_user_if_needed \
      ${OVNCTL_PATH} run_nb_ovsdb --no-monitor \
      --ovn-nb-log="${ovn_log_nb}" &

  wait_for_event attempts=3 process_ready ovnnb_db
  echo "=============== nb-ovsdb ========== RUNNING"
  sleep 3

  ovn_db_host=$(getent ahosts $(hostname) | head -1 | awk '{ print $1 }')
  ovn-nbctl set-connection ptcp:${ovn_nb_port}:${ovn_db_host} -- set connection . inactivity_probe=0

  tail --follow=name ${OVN_LOGDIR}/ovsdb-server-nb.log &
  ovn_tail_pid=$!

  process_healthy ovnnb_db ${ovn_tail_pid}
  echo "=============== run nb_ovsdb ========== terminated"
}

# v3 - run sb_ovsdb in a separate container
sb-ovsdb () {
  trap 'kill $(jobs -p); exit 0' TERM
  check_ovn_daemonset_version "3"
  rm -f ${OVN_RUNDIR}/ovnsb_db.pid

  # Make sure /var/lib/openvswitch exists
  mkdir -p /var/lib/openvswitch

  iptables-rules ${ovn_sb_port}

  echo "=============== run sb_ovsdb ========== MASTER ONLY"
  run_as_ovs_user_if_needed \
      ${OVNCTL_PATH} run_sb_ovsdb --no-monitor     \
      --ovn-sb-log="${ovn_log_sb}" &

  wait_for_event attempts=3 process_ready ovnsb_db
  echo "=============== sb-ovsdb ========== RUNNING"
  sleep 3

  ovn_db_host=$(getent ahosts $(hostname) | head -1 | awk '{ print $1 }')
  ovn-sbctl set-connection ptcp:${ovn_sb_port}:${ovn_db_host} -- set connection . inactivity_probe=0

  # create the ovnkube_db endpoint for other pods to query the OVN DB IP
  set_ovnkube_db_ep

  tail --follow=name ${OVN_LOGDIR}/ovsdb-server-sb.log &
  ovn_tail_pid=$!

  process_healthy ovnsb_db ${ovn_tail_pid}
  echo "=============== run sb_ovsdb ========== terminated"
}


# v3 - Runs northd on master. Does not run nb_ovsdb, and sb_ovsdb
run-ovn-northd () {
  check_ovn_daemonset_version "3"
  rm -f ${OVN_RUNDIR}/ovn-northd.pid
  rm -f ${OVN_RUNDIR}/ovn-northd.*.ctl

  # Make sure /var/lib/openvswitch exists
  mkdir -p /var/lib/openvswitch

  echo "=============== run-ovn-northd (wait for ready_to_start_node)"
  wait_for_event ready_to_start_node

  sleep 1

  echo "=============== run_ovn_northd ========== MASTER ONLY"
  echo "ovn_db_host ${ovn_db_host}"
  echo "ovn_nbdb ${ovn_nbdb}   ovn_sbdb ${ovn_sbdb}"
  echo "ovn_northd_opts=${ovn_northd_opts}"
  echo "ovn_log_northd=${ovn_log_northd}"

  # no monitor (and no detach), start northd which connects to the
  # ovnkube-db service
  ovn_nbdb_i=$(echo ${ovn_nbdb} | sed 's;//;;')
  ovn_sbdb_i=$(echo ${ovn_sbdb} | sed 's;//;;')
  run_as_ovs_user_if_needed \
      ${OVNCTL_PATH} start_northd \
      --no-monitor --ovn-manage-ovsdb=no \
      --ovn-northd-nb-db=${ovn_nbdb_i} --ovn-northd-sb-db=${ovn_sbdb_i} \
      --ovn-northd-log="${ovn_log_northd}" \
    ${ovn_northd_opts}

  wait_for_event attempts=3 process_ready ovn-northd
  echo "=============== run_ovn_northd ========== RUNNING"
  sleep 1

  tail --follow=name ${OVN_LOGDIR}/ovn-northd.log &
  ovn_tail_pid=$!


  process_healthy ovn-northd ${ovn_tail_pid}
  exit 8
}


# make sure the specified dport is open
iptables-rules () {
  dport=$1
  iptables -C INPUT -p tcp -m tcp --dport $dport -m conntrack --ctstate NEW -j ACCEPT
  if [[ $? != 0 ]] ; then
    iptables -I INPUT -p tcp -m tcp --dport $dport -m conntrack --ctstate NEW -j ACCEPT
  fi
}

# v3 - run ovnkube --master
ovn-master () {
  trap 'kill $(jobs -p); exit 0' TERM
  check_ovn_daemonset_version "3"
  rm -f ${OVN_RUNDIR}/ovnkube-master.pid

  echo "=============== ovn-master (wait for ready_to_start_node) ========== MASTER ONLY"
  wait_for_event ready_to_start_node
  echo "ovn_nbdb ${ovn_nbdb}   ovn_sbdb ${ovn_sbdb}"

  # wait for northd to start
  wait_for_event process_ready ovn-northd

  echo "=============== ovn-master (wait for ovn-nbctl daemon) ========== MASTER ONLY"
  wait_for_event process_ready ovn-nbctl

  sleep 5

  # wait for ovs-servers to start since ovn-master sets some fields in OVS DB
  echo "=============== ovn-master - (wait for ovs)"
  wait_for_event ovs_ready

  hybrid_overlay_flags=
  if [[ -n "${ovn_hybrid_overlay_enable}" ]]; then
    hybrid_overlay_flags="--enable-hybrid-overlay"
    if [[ -n "${ovn_hybrid_overlay_net_cidr}" ]]; then
      hybrid_overlay_flags="${hybrid_overlay_flags} --hybrid-overlay-cluster-subnets=${ovn_hybrid_overlay_net_cidr}"
    fi
  fi

  echo "=============== ovn-master ========== MASTER ONLY"
  /usr/bin/ovnkube \
    --init-master ${ovn_pod_host} \
    --cluster-subnets ${net_cidr} --k8s-service-cidr=${svc_cidr} \
    --nb-address=${ovn_nbdb} --sb-address=${ovn_sbdb} \
    --nodeport \
    --nbctl-daemon-mode \
    --loglevel=${ovnkube_loglevel} \
    ${hybrid_overlay_flags} \
    --pidfile ${OVN_RUNDIR}/ovnkube-master.pid \
    --logfile /var/log/ovn-kubernetes/ovnkube-master.log \
    --metrics-bind-address "0.0.0.0:9102" &
  echo "=============== ovn-master ========== running"
  wait_for_event attempts=3 process_ready ovnkube-master
  sleep 1

  tail --follow=name /var/log/ovn-kubernetes/ovnkube-master.log &
  kube_tail_pid=$!

  process_healthy ovnkube-master ${kube_tail_pid}
  exit 9
}

# ovn-controller - all nodes
ovn-controller () {
  check_ovn_daemonset_version "3"
  rm -f ${OVN_RUNDIR}/ovn-controller.pid

  echo "=============== ovn-controller - (wait for ovs)"
  wait_for_event ovs_ready

  echo "=============== ovn-controller - (wait for ready_to_start_node)"
  wait_for_event ready_to_start_node

  echo "ovn_nbdb ${ovn_nbdb}   ovn_sbdb ${ovn_sbdb}"
  echo "ovn_nbdb_test ${ovn_nbdb_test}"

  echo "=============== ovn-controller  start_controller"
  rm -f /var/run/ovn-kubernetes/cni/*
  rm -f ${OVN_RUNDIR}/ovn-controller.*.ctl

  run_as_ovs_user_if_needed \
      ${OVNCTL_PATH} --no-monitor start_controller \
               --ovn-controller-log="${ovn_log_controller}" \
               ${ovn_controller_opts}

  wait_for_event attempts=3 process_ready ovn-controller
  echo "=============== ovn-controller ========== running"

  sleep 4
  tail --follow=name ${OVN_LOGDIR}/ovn-controller.log &
  controller_tail_pid=$!

  process_healthy ovn-controller ${controller_tail_pid}
  exit 10
}



# ovn-node - all nodes
ovn-node () {
  trap 'kill $(jobs -p) ; rm -f /etc/cni/net.d/10-ovn-kubernetes.conf ; exit 0' TERM
  check_ovn_daemonset_version "3"
  rm -f ${OVN_RUNDIR}/ovnkube.pid

  echo "=============== ovn-node - (wait for ovs)"
  wait_for_event ovs_ready

  echo "=============== ovn-node - (wait for ready_to_start_node)"
  wait_for_event ready_to_start_node

  echo "ovn_nbdb ${ovn_nbdb}   ovn_sbdb ${ovn_sbdb}  ovn_nbdb_test ${ovn_nbdb_test}"

  echo "=============== ovn-node - (ovn-node  wait for ovn-controller.pid)"
  wait_for_event process_ready ovn-controller
  sleep 1

  hybrid_overlay_flags=
  if [[ -n "${ovn_hybrid_overlay_enable}" ]]; then
    hybrid_overlay_flags="--enable-hybrid-overlay"
  fi

  echo "=============== ovn-node   --init-node"
  /usr/bin/ovnkube --init-node ${K8S_NODE} \
      --cluster-subnets ${net_cidr} --k8s-service-cidr=${svc_cidr} \
      --nb-address=${ovn_nbdb} --sb-address=${ovn_sbdb} \
      --nodeport \
      --mtu=${mtu} \
      --loglevel=${ovnkube_loglevel} \
      ${hybrid_overlay_flags} \
      --gateway-mode=${ovn_gateway_mode} ${ovn_gateway_opts}  \
      --pidfile ${OVN_RUNDIR}/ovnkube.pid \
      --logfile /var/log/ovn-kubernetes/ovnkube.log \
      --metrics-bind-address "0.0.0.0:9101" &

  wait_for_event attempts=3 process_ready ovnkube
  setup_cni
  echo "=============== ovn-node ========== running"

  sleep 5
  tail --follow=name /var/log/ovn-kubernetes/ovnkube.log &
  node_tail_pid=$!

  process_healthy ovnkube ${node_tail_pid}
  exit 7
}

# cleanup-ovn-node - all nodes
cleanup-ovn-node () {
  check_ovn_daemonset_version "3"

  rm -f /etc/cni/net.d/10-ovn-kubernetes.conf

  echo "=============== time: $(date +%d-%m-%H:%M:%S:%N) cleanup-ovn-node - (wait for ovn-controller to exit)"
  retries=0
  while [[ ${retries} -lt 80 ]]; do
    process_ready ovn-controller
    if [[ $? != 0 ]] ; then
      break
    fi
    echo "=============== time: $(date +%d-%m-%H:%M:%S:%N) cleanup-ovn-node - (ovn-controller still running, wait)"
    sleep 1
    (( retries += 1 ))
  done

  echo "=============== time: $(date +%d-%m-%H:%M:%S:%N) cleanup-ovn-node --cleanup-node"
  /usr/bin/ovnkube --cleanup-node ${K8S_NODE} --gateway-mode=${ovn_gateway_mode} ${ovn_gateway_opts} \
      --k8s-token=${k8s_token} --k8s-apiserver=${K8S_APISERVER} --k8s-cacert=${K8S_CACERT} \
      --loglevel=${ovnkube_loglevel} \
      --logfile /var/log/ovn-kubernetes/ovnkube.log

}

# v3 - Runs ovn-nbctl in daemon mode
run-nbctld () {
  check_ovn_daemonset_version "3"
  rm -f ${OVN_RUNDIR}/ovn-nbctl.pid
  rm -f ${OVN_RUNDIR}/ovn-nbctl.*.ctl

  echo "=============== run-nbctld - (wait for ready_to_start_node)"
  wait_for_event ready_to_start_node

  echo "ovn_nbdb ${ovn_nbdb}   ovn_sbdb ${ovn_sbdb}  ovn_nbdb_test ${ovn_nbdb_test}"
  echo "ovn_log_nbctld=${ovn_log_nbctld}"

  # use unix socket
  /usr/bin/ovn-nbctl --pidfile --detach --db=${ovn_nbdb_test} --log-file=${ovn_log_nbctld}

  wait_for_event attempts=3 process_ready ovn-nbctl
  echo "=============== run_ovn_nbctl ========== RUNNING"

  tail --follow=name ${OVN_LOGDIR}/ovn-nbctl.log &
  nbctl_tail_pid=$!

  process_healthy ovn-nbctl ${nbctl_tail_pid}
  echo "=============== run_ovn_nbctl ========== terminated"
}

echo "================== ovnkube.sh --- version: ${ovnkube_version} ================"

  echo " ==================== command: ${cmd}"
  display_version

  # display_env

# Start the requested daemons
# daemons come up in order
# ovs-db-server  - all nodes  -- not done by this script (v3)
# ovs-vswitchd   - all nodes  -- not done by this script (v3)
#  run-ovn-northd Runs ovn-northd as a process does not run nb_ovsdb or sb_ovsdb (v3)
#  nb-ovsdb       Runs nb_ovsdb as a process (no detach or monitor) (v3)
#  sb-ovsdb       Runs sb_ovsdb as a process (no detach or monitor) (v3)
# ovn-master     - master node only (v3)
# ovn-controller - all nodes (v3)
# ovn-node       - all nodes (v3)
# cleanup-ovn-node - all nodes (v3)

  case ${cmd} in
    "nb-ovsdb")        # pod ovnkube-db container nb-ovsdb
	nb-ovsdb
    ;;
    "sb-ovsdb")        # pod ovnkube-db container sb-ovsdb
	sb-ovsdb
    ;;
    "run-ovn-northd")  # pod ovnkube-master container run-ovn-northd
	run-ovn-northd
    ;;
    "ovn-master")      # pod ovnkube-master container ovnkube-master
	ovn-master
    ;;
    "ovs-server")      # pod ovnkube-node container ovs-daemons
        ovs-server
    ;;
    "ovn-controller")  # pod ovnkube-node container ovn-controller
	ovn-controller
    ;;
    "ovn-node")        # pod ovnkube-node container ovn-node
	ovn-node
    ;;
    "run-nbctld")   # pod ovnkube-master container run-nbctld
    run-nbctld
    ;;
    "ovn-northd")
	ovn-northd
    ;;
    "display_env")
        display_env
	exit 0
    ;;
    "display")
	display
	exit 0
    ;;
    "ovn_debug")
	ovn_debug
	exit 0
    ;;
    "cleanup-ovs-server")
	cleanup-ovs-server
    ;;
    "cleanup-ovn-node")
	cleanup-ovn-node
    ;;
    *)
	echo "invalid command ${cmd}"
	echo "valid v3 commands: ovs-server nb-ovsdb sb-ovsdb run-ovn-northd ovn-master ovn-controller ovn-node display_env display ovn_debug cleanup-ovs-server cleanup-ovn-node"
	exit 0
  esac

exit 0
