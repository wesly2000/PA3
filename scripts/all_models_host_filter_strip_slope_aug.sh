#!/bin/bash

# Best coverage
# TF=4, DF=4, RF=4

root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"
iter_num=8

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
NetCLR|size_bin|size|size
DF|size_bin|size|size
TF|size_bin|size|size
RF|tsam|tsam|tsam
BAPM|size_bin|size|size
TikTok|dt|dt|dt
'

coverage=4

printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    # Host Filter + Strip + Host Filter Strategy
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_host_filter_strip.npz" "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_host_filter_strip_aug_slope_shadowsocks_gaussian.npz" "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_shadowsocks_gaussian.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_host_filter_strip_aug_slope_trojan_gaussian.npz" "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_trojan_gaussian.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_host_filter_strip.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_host_filter_strip.npz" "${root_dir}/workspace/trojan_${model_feature}_host_filter_strip.npz"

    # Merge VMess datasets
    python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip.npz ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_shadowsocks_gaussian.npz ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_trojan_gaussian.npz -o ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian.npz

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_host_filter_strip

    if [ "${model}" = "NetCLR" ]; then
        i=1
        while [ "$i" -le "$iter_num" ]; do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip/${model}"
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian ${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian ${root_dir}/workspace/trojan_${model_feature}_host_filter_strip ${model_feature} cuda:0
            i=$((i + 1))
        done
    else
        i=1
        while [ "$i" -le "$iter_num" ]; do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian ${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian ${root_dir}/workspace/trojan_${model_feature}_host_filter_strip ${model_feature} cuda:0
            i=$((i + 1))
        done
    fi

    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_shadowsocks_gaussian.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_trojan_gaussian.npz"
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip.npz"
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_host_filter_strip.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip"
    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_gaussian"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_host_filter_strip"
done