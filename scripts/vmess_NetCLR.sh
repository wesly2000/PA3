#!/bin/bash

# Best coverage
# TF=4, DF=4, RF=4

root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"
iter_num=8

# Copy only when destination is missing; rm only when path exists.
copy_npz_if_missing() {
    local src=$1 dst=$2
    [ -f "$dst" ] || cp -- "$src" "$dst"
}
rm_file_if_exists() {
    local f=$1
    [ -f "$f" ] && rm -- "$f"
}
rm_dir_if_exists() {
    local d=$1
    [ -d "$d" ] && rm -r -- "$d"
}

# Each row: model|model_feature|split_feature|file_feature (Python zip of the four fields, reversed).
MODEL_CONFIGS=(
    "RF|tsam|tsam|tsam"                # RF + TSAM
    "BAPM|size_bin|size|size"          # BAPM + size_bin
    "TF|size_bin|size|size"            # TF + size_bin
    "DF|size_bin|size|size"            # DF + size_bin
    "TikTok|dt|dt|dt"                  # TikTok + dt
)

coverage=4

for _cfg_row in "${MODEL_CONFIGS[@]}"; do
    IFS='|' read -r model model_feature split_feature file_feature <<< "$_cfg_row"
    # Augmentation + Strip + Size Filter Strategy
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}_aug.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz"

    python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug.npz" -o "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug

    for ((i=1; i<=iter_num; i++)); do
        rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug/${model}"
        rm_dir_if_exists "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug/${model}"

        ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug
        ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
        ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
    done

    rm_file_if_exists "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug.npz"
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}"
done