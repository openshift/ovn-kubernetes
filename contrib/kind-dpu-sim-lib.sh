#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright The OVN-Kubernetes Contributors
# SPDX-License-Identifier: Apache-2.0

restart_dpu_sim_multus_after_ovnk() {
  if [ "${DPU_MODE:-none}" == "none" ] || [ "${ENABLE_MULTI_NET:-false}" != true ]; then
    return
  fi

  if ! kubectl -n kube-system get daemonset kube-multus-ds >/dev/null 2>&1; then
    return
  fi

  echo "Restarting dpu-simulator Multus after OVN-Kubernetes is ready..."
  kubectl -n kube-system rollout restart daemonset/kube-multus-ds
  kubectl -n kube-system rollout status daemonset/kube-multus-ds --timeout 2m
}

resume_dpu_sim_system_deployment() {
  local namespace=$1
  local name=$2
  local kubeconfig=${3:-}
  local kubectl_cmd=(kubectl)

  if [ -n "${kubeconfig}" ]; then
    kubectl_cmd=(kubectl --kubeconfig "${kubeconfig}")
  fi

  if ! "${kubectl_cmd[@]}" -n "${namespace}" get deployment "${name}" >/dev/null 2>&1; then
    return
  fi

  local replicas
  replicas=$("${kubectl_cmd[@]}" -n "${namespace}" get deployment "${name}" -o jsonpath='{.metadata.annotations.dpu-sim\.io/suspend-replicas}')
  if [ -n "${replicas}" ]; then
    echo "Restoring dpu-simulator deployment ${namespace}/${name} to ${replicas} replicas..."
    "${kubectl_cmd[@]}" -n "${namespace}" patch deployment "${name}" --type=json -p="[{\"op\":\"replace\",\"path\":\"/spec/replicas\",\"value\":${replicas}},{\"op\":\"remove\",\"path\":\"/metadata/annotations/dpu-sim.io~1suspend-replicas\"}]"
  fi

  "${kubectl_cmd[@]}" -n "${namespace}" rollout restart deployment/"${name}"
  "${kubectl_cmd[@]}" -n "${namespace}" rollout status deployment/"${name}" --timeout 2m
}

restart_dpu_sim_system_deployments_after_ovnk() {
  if [ "${DPU_MODE:-none}" == "none" ]; then
    return
  fi

  if [ "${DPU_MODE}" == "host" ]; then
    echo "Leaving dpu-simulator host system deployments suspended until DPU OVN-Kubernetes is installed"
    return
  fi

  resume_dpu_sim_system_deployment kube-system coredns
  resume_dpu_sim_system_deployment local-path-storage local-path-provisioner

  if [ "${DPU_MODE}" == "dpu" ] && [ -n "${FRR_K8S_HOST_KUBECONFIG:-}" ]; then
    echo "Restoring dpu-simulator host system deployments after DPU OVN-Kubernetes is ready..."
    resume_dpu_sim_system_deployment kube-system coredns "${FRR_K8S_HOST_KUBECONFIG}"
    resume_dpu_sim_system_deployment local-path-storage local-path-provisioner "${FRR_K8S_HOST_KUBECONFIG}"
  fi
}

frr_k8s_remote_enabled() {
  [[ -n "${FRR_K8S_REMOTE_KUBECONFIG:-}" || -n "${FRR_K8S_REMOTE_NODE_MAP:-}" ]]
}

validate_frr_k8s_remote() {
  if ! frr_k8s_remote_enabled; then
    return
  fi
  if [[ -z "${FRR_K8S_REMOTE_KUBECONFIG:-}" || -z "${FRR_K8S_REMOTE_NODE_MAP:-}" ]]; then
    echo "FRR-K8S remote mode requires both FRR_K8S_REMOTE_KUBECONFIG and FRR_K8S_REMOTE_NODE_MAP" >&2
    exit 1
  fi
  if [[ ! -f "${FRR_K8S_REMOTE_KUBECONFIG}" ]]; then
    echo "FRR-K8S remote kubeconfig does not exist: ${FRR_K8S_REMOTE_KUBECONFIG}" >&2
    exit 1
  fi
  if [[ -n "${FRR_K8S_HOST_KUBECONFIG:-}" && ! -f "${FRR_K8S_HOST_KUBECONFIG}" ]]; then
    echo "FRR-K8S host kubeconfig does not exist: ${FRR_K8S_HOST_KUBECONFIG}" >&2
    exit 1
  fi
}

frr_k8s_host_kubeconfig() {
  printf '%s' "${FRR_K8S_HOST_KUBECONFIG:-${FRR_K8S_REMOTE_KUBECONFIG}}"
}

ensure_frr_k8s_namespace() {
  local kubeconfig=${1:-}
  local kubectl_cmd=(kubectl)
  if [ -n "${kubeconfig}" ]; then
    kubectl_cmd=(kubectl --kubeconfig "${kubeconfig}")
  fi

  "${kubectl_cmd[@]}" create namespace frr-k8s-system --dry-run=client -o yaml | \
    "${kubectl_cmd[@]}" apply -f -
}

install_frr_k8s_host_api_crds() {
  validate_frr_k8s_remote
  if ! frr_k8s_remote_enabled; then
    return
  fi

  echo "Installing frr-k8s CRDs into the remote host API ..."
  local host_kubeconfig
  host_kubeconfig=$(frr_k8s_host_kubeconfig)
  ensure_frr_k8s_namespace "${host_kubeconfig}"
  kubectl --kubeconfig "${host_kubeconfig}" apply \
    -f "${FRR_TMP_DIR}"/frr-k8s/config/crd/bases/
  ensure_frr_k8s_host_api_rbac "${host_kubeconfig}"
}

ensure_frr_k8s_host_api_rbac() {
  local host_kubeconfig=$1

  local frr_rbac_dir="${FRR_TMP_DIR}/frr-k8s/config/rbac"
  local host_rbac_dir="${FRR_TMP_DIR}/frr-k8s/config/host-api-rbac"
  mkdir -p "${host_rbac_dir}"
  cp \
    "${frr_rbac_dir}/service_account.yaml" \
    "${frr_rbac_dir}/role.yaml" \
    "${frr_rbac_dir}/secrets_role.yaml" \
    "${frr_rbac_dir}/role_binding.yaml" \
    "${host_rbac_dir}/"
  cat > "${host_rbac_dir}/kustomization.yaml" <<'EOF'
namespace: frr-k8s-system
namePrefix: frr-k8s-
resources:
- service_account.yaml
- role.yaml
- secrets_role.yaml
- role_binding.yaml
EOF

  kubectl --kubeconfig "${host_kubeconfig}" apply -k "${host_rbac_dir}"
}

create_frr_k8s_remote_kubeconfig_secret() {
  validate_frr_k8s_remote
  if ! frr_k8s_remote_enabled; then
    return
  fi

  kubectl -n frr-k8s-system create secret generic frr-k8s-host-kubeconfig \
    --from-file=kubeconfig="${FRR_K8S_REMOTE_KUBECONFIG}" \
    --dry-run=client -o yaml | kubectl apply -f -
}

configure_frr_k8s_remote_daemonsets() {
  validate_frr_k8s_remote
  if ! frr_k8s_remote_enabled; then
    return
  fi

  local source_json="${FRR_TMP_DIR}/frr-k8s-daemon.json"
  kubectl -n frr-k8s-system get daemonset frr-k8s-daemon -o json > "${source_json}"
  kubectl -n frr-k8s-system delete daemonset -l dpu-sim.ovn.org/frr-remote=true --ignore-not-found

  local pair host_node dpu_node safe_name ds_name
  IFS=',' read -ra pairs <<< "${FRR_K8S_REMOTE_NODE_MAP}"
  for pair in "${pairs[@]}"; do
    host_node="${pair%%=*}"
    dpu_node="${pair#*=}"
    if [[ -z "${host_node}" || -z "${dpu_node}" || "${pair}" != *"="* ]]; then
      echo "Invalid FRR_K8S_REMOTE_NODE_MAP entry: ${pair}" >&2
      exit 1
    fi
    safe_name=$(printf '%s' "${host_node}" | tr '[:upper:]' '[:lower:]' | sed 's/[^a-z0-9-]/-/g' | sed 's/^-*//;s/-*$//')
    if [[ -z "${safe_name}" ]]; then
      echo "Invalid host node name for FRR_K8S_REMOTE_NODE_MAP entry: ${pair}" >&2
      exit 1
    fi
    ds_name="frr-k8s-daemon-${safe_name:0:45}"
    echo "Creating remote frr-k8s daemonset ${ds_name}: host node ${host_node}, DPU node ${dpu_node}"
    # These DaemonSets run in the DPU cluster. Only the FRR-K8S
    # controller container uses the host API so it watches host
    # FRRConfiguration objects with the host node name. Keep frr-status
    # on the DPU API because it reports the local daemon pod status.
    jq \
      --arg name "${ds_name}" \
      --arg host_node "${host_node}" \
      --arg dpu_node "${dpu_node}" \
      'del(.metadata.uid, .metadata.resourceVersion, .metadata.generation, .metadata.creationTimestamp, .metadata.managedFields, .status)
       | .metadata.name = $name
       | .metadata.labels["dpu-sim.ovn.org/frr-remote"] = "true"
       | .metadata.labels["dpu-sim.ovn.org/frr-host-node"] = $host_node
       | .spec.selector.matchLabels["dpu-sim.ovn.org/frr-host-node"] = $host_node
       | .spec.template.metadata.labels["dpu-sim.ovn.org/frr-remote"] = "true"
       | .spec.template.metadata.labels["dpu-sim.ovn.org/frr-host-node"] = $host_node
       | .spec.template.metadata.annotations["kubectl.kubernetes.io/default-container"] = "controller"
       | .spec.template.spec.nodeSelector = {"kubernetes.io/hostname": $dpu_node}
       | (.spec.template.spec.containers[] | select(.name == "frr-k8s" or .name == "controller").args) |= ((. // []) | map(if startswith("--node-name=") then "--node-name=" + $host_node else . end))
       | (.spec.template.spec.containers[] | select(.name == "frr-k8s" or .name == "controller").env) |= ((. // []) + [{"name":"KUBECONFIG","value":"/var/run/host-kubeconfig/kubeconfig"}])
       | (.spec.template.spec.containers[] | select(.name == "frr-k8s" or .name == "controller").volumeMounts) |= ((. // []) + [{"name":"host-kubeconfig","mountPath":"/var/run/host-kubeconfig","readOnly":true}])
       | .spec.template.spec.volumes = ((.spec.template.spec.volumes // []) + [{"name":"host-kubeconfig","secret":{"secretName":"frr-k8s-host-kubeconfig"}}])' \
      "${source_json}" | kubectl apply -f -
  done

  kubectl -n frr-k8s-system delete daemonset frr-k8s-daemon --ignore-not-found
}
