#!/bin/bash

# Best coverage
# TF=4, DF=4, RF=4

root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"
iter_num=1

# Copy only when destination is missing; rm only when path exists.
copy_npz_if_missing() {
    src=$1
    dst=$2
    [ -f "$dst" ] || cp -- "$src" "$dst"
}
rm_file_if_exists() {
    f=$1
    [ -f "$f" ] && rm -- "$f"
}
rm_dir_if_exists() {
    d=$1
    [ -d "$d" ] && rm -r -- "$d"
}

# Each row: model|model_feature|split_feature|file_feature.
MODEL_CONFIGS='
BAPM|size_bin|size|size
TF|size_bin|size|size
NetCLR|size_bin|size|size
'

# BAPM|size_bin|size|size
# DF|size_bin|size|size
# RF|tsam|tsam|tsam
# TF|size_bin|size|size
# TikTok|dt|dt|dt
# NetCLR|size_bin|size|size

printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    # Size Filter Strategy
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}.npz" "${root_dir}/workspace/vmess_${model_feature}.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}.npz" "${root_dir}/workspace/trojan_${model_feature}.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}

    while [ "$i" -le "$iter_num" ]; do
        rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}/${model}"

        ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature} ${model_feature} cuda:0
        ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0
        ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0
        i=$((i + 1))
    done
done

printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}.npz"
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}.npz"
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}"
done