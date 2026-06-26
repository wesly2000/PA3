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
DF|size_bin|size|size
'

# NetCLR|size_bin|size|size
# BAPM|size_bin|size|size
# TF|size_bin|size|size
# TikTok|dt|dt|dt
# RF|tsam|tsam|tsam

# No op
## VMess as the training dataset, Shadowsocks and Trojan as the test dataset
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}.npz" "${root_dir}/workspace/vmess_${model_feature}.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}.npz" "${root_dir}/workspace/trojan_${model_feature}.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}

    i=1
    while [ "$i" -le "$iter_num" ]; do
        rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}/${model}"

        ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature} ${model_feature} cuda:0
        ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0
        ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0
        i=$((i + 1))
    done
done

## Clean up
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}.npz"
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}.npz"
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}"
done


vmess_coverage=4
shadowsocks_coverage=4
trojan_coverage=4

# Size Filter Strategy
# VMess as training set, Shadowsocks and Trojan as testing set
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_${shadowsocks_coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${shadowsocks_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_${trojan_coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_${trojan_coverage}.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${shadowsocks_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${trojan_coverage}
    if [ "${model}" = "NetCLR" ]; then
        i=1
        while [ "$i" -le "$iter_num" ]; do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage}/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage} ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${trojan_coverage} ${model_feature} cuda:0
            i=$((i + 1))
        done
    else
        i=1
        while [ "$i" -le "$iter_num" ]; do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage}/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${trojan_coverage} ${model_feature} cuda:0
            i=$((i + 1))
        done
    fi
done

# Cleanup for Size Filter Strategy
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${shadowsocks_coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_${trojan_coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_${vmess_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${shadowsocks_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_${trojan_coverage}"
done

# Size Filter + Strip Strategy
# VMess as training set, Shadowsocks and Trojan as testing set
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${shadowsocks_coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${trojan_coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}

    if [ "${model}" = "NetCLR" ]; then
        i=1
        while [ "$i" -le "$iter_num" ]; do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage} ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
            i=$((i + 1))
        done
    else
        i=1
        while [ "$i" -le "$iter_num" ]; do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
            i=$((i + 1))
        done
   
    fi
done

# Cleanup for Size Filter + Strip Strategy
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}"
done


# Augmentation + Strip + Size Filter Strategy
# 1. VMess train, Shadowsocks/Trojan test (original)
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${shadowsocks_coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${trojan_coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan.npz" -o "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}

    if [[ "${model}" = "NetCLR" ]]; then 
        for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}/${model}"
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    else 
        for ((i=1; i<=iter_num; i++)); do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    fi
done

# Cleanup for all
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    # VMess workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan.npz"
    # Shadowsocks workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    # Trojan workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope"
    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}"
done

# Augmentation + Strip + Size Filter Strategy
# 1. VMess train, Shadowsocks/Trojan test (original)
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks_gaussian.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks_gaussian.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan_gaussian.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan_gaussian.npz"
    copy_npz_if_missing "${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan.npz"
    copy_npz_if_missing "${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${shadowsocks_coverage}.npz" "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    copy_npz_if_missing "${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${trojan_coverage}.npz" "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks_gaussian.npz" "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan_gaussian.npz" -o "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian.npz"

    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}
    python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}

    if [[ "${model}" = "NetCLR" ]]; then 
        for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}/${model}"
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    else 
        for ((i=1; i<=iter_num; i++)); do
            rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian/${model}"

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage} ${model_feature} cuda:0
        done
    fi
done

# Cleanup for all
printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    # VMess workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks_gaussian.npz"
    rm_file_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_trojan_gaussian.npz"
    # Shadowsocks workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}.npz"
    # Trojan workspace cleanup
    rm_file_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}.npz"

    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}_aug_slope_gaussian"
    rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${vmess_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${shadowsocks_coverage}"
    rm_dir_if_exists "${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${trojan_coverage}"
done