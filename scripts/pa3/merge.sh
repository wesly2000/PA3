#!/bin/bash

_pa3_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_pa3_script_dir}/_load_env.sh" ]]; then
    source "${_pa3_script_dir}/_load_env.sh"
else
    source "${_pa3_script_dir}/../_load_env.sh"
fi

python exp/dataset_process/dataset_merge.py -i ${PA3_REPO_ROOT}/Reproduce/features/vmess/size_pa3_trojan.npz ${PA3_REPO_ROOT}/Reproduce/features/vmess/size_pa3_shadowsocks.npz -o ${PA3_REPO_ROOT}/Reproduce/features/vmess/size_pa3.npz

python exp/dataset_process/dataset_merge.py -i ${PA3_REPO_ROOT}/Reproduce/features/shadowsocks/size_pa3_trojan.npz ${PA3_REPO_ROOT}/Reproduce/features/shadowsocks/size_pa3_vmess.npz -o ${PA3_REPO_ROOT}/Reproduce/features/shadowsocks/size_pa3.npz

python exp/dataset_process/dataset_merge.py -i ${PA3_REPO_ROOT}/Reproduce/features/trojan/size_pa3_vmess.npz ${PA3_REPO_ROOT}/Reproduce/features/trojan/size_pa3_shadowsocks.npz -o ${PA3_REPO_ROOT}/Reproduce/features/trojan/size_pa3.npz

python exp/dataset_process/dataset_merge.py -i ${PA3_REPO_ROOT}/Reproduce/features/vmess/tsam_pa3_trojan.npz ${PA3_REPO_ROOT}/Reproduce/features/vmess/tsam_pa3_shadowsocks.npz -o ${PA3_REPO_ROOT}/Reproduce/features/vmess/tsam_pa3.npz

python exp/dataset_process/dataset_merge.py -i ${PA3_REPO_ROOT}/Reproduce/features/shadowsocks/tsam_pa3_trojan.npz ${PA3_REPO_ROOT}/Reproduce/features/shadowsocks/tsam_pa3_vmess.npz -o ${PA3_REPO_ROOT}/Reproduce/features/shadowsocks/tsam_pa3.npz

python exp/dataset_process/dataset_merge.py -i ${PA3_REPO_ROOT}/Reproduce/features/trojan/tsam_pa3_vmess.npz ${PA3_REPO_ROOT}/Reproduce/features/trojan/tsam_pa3_shadowsocks.npz -o ${PA3_REPO_ROOT}/Reproduce/features/trojan/tsam_pa3.npz
