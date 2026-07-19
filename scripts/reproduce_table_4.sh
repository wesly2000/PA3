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
DF|size_bin|size|size
BAPM|size_bin|size|size
TF|size_bin|size|size
NetCLR|size_bin|size|size
TikTok|dt|dt|dt
RF|tsam|tsam|tsam
'

# BAPM|size_bin|size|size
# TF|size_bin|size|size
# NetCLR|size_bin|size|size
# TikTok|dt|dt|dt
# RF|tsam|tsam|tsam


vmess_coverage=4
shadowsocks_coverage=4
trojan_coverage=4

# NoProxy Augmentation + Strip + Size Filter Strategy
# 1. VMess train, Shadowsocks/Trojan test (original)
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${shadowsocks_coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${trojan_coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    python exp/dataset_process/dataset_merge.py -i "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy.npz" -o "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}

    if [[ "${model}" = "NetCLR" ]]; then 
        for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}/${model}"
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    else 
        for ((i=1; i<=iter_num; i++)); do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    fi
done

# Cleanup for all
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    # VMess workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    # Shadowsocks workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    # Trojan workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_noproxy"
    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}"
done

# Known Slope Augmentation + Strip + Size Filter Strategy
# 1. VMess train, Shadowsocks/Trojan test (original)
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope_shadowsocks.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope_shadowsocks.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope_trojan.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope_trojan.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${shadowsocks_coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${trojan_coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    python exp/dataset_process/dataset_merge.py -i "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope_shadowsocks.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope_trojan.npz" -o "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}

    if [[ "${model}" = "NetCLR" ]]; then 
        for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}/${model}"
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    else 
        for ((i=1; i<=iter_num; i++)); do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    fi
done

# Cleanup for all
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    # VMess workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    # Shadowsocks workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    # Trojan workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_known_slope"
    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}"
done


# No CDF-based Augmentation + Strip + Size Filter Strategy
# 1. VMess train, Shadowsocks/Trojan test (original)
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${shadowsocks_coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${trojan_coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    python exp/dataset_process/dataset_merge.py -i "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf.npz" -o "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}

    if [[ "${model}" = "NetCLR" ]]; then 
        for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}/${model}"
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    else 
        for ((i=1; i<=iter_num; i++)); do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    fi
done

# Cleanup for all
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    # VMess workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    # Shadowsocks workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    # Trojan workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_no_cdf"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}"
done


# CDF-based Augmentation + Strip + Size Filter Strategy
# 1. VMess train, Shadowsocks/Trojan test (original)
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${shadowsocks_coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${trojan_coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    python exp/dataset_process/dataset_merge.py -i "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf.npz" -o "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}

    if [[ "${model}" = "NetCLR" ]]; then 
        for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}/${model}"
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    else 
        for ((i=1; i<=iter_num; i++)); do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    fi
done

# Cleanup for all
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    # VMess workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    # Shadowsocks workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    # Trojan workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_cdf"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}"
done