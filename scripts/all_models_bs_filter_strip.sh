#!/bin/bash

# Best coverage
# TF=4, DF=4, RF=4

root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"
iter_num=3

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
RF|tsam|tsam|tsam
TF|size_bin|size|size
NetCLR|size_bin|size|size
BAPM|size_bin|size|size
TikTok|dt|dt|dt
DF|size_bin|size|size
'

coverage=4

printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    # Size Filter + Strip + Host Filter Strategy
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

    if [ "${model}" = "NetCLR" ]; then
        i=1
        while [ "$i" -le "$iter_num" ]; do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
            i=$((i + 1))
        done
    else
        i=1
        while [ "$i" -le "$iter_num" ]; do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
            i=$((i + 1))
        done
    fi

    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}"
done