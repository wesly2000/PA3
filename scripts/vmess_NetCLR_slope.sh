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
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz"

    python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz" -o "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug_slope.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug_slope
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}

    for ((i=1; i<=iter_num; i++)); do
        rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}/${model}"
        rm_dir_if_exists "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug_slope/${model}"

        ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug_slope ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
        ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug_slope ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
        ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug_slope ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
    done

    rm_file_if_exists "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug_slope.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz"
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}_aug_slope"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}"
done