#!/bin/bash

# Example usage:
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw.npz
# Function to generate size, dt, tsam versions from raw .npz input.
# Replaces the leading "raw" in the basename (e.g. raw_bs_filter_4.npz -> size_bs_filter_4.npz).
gen_all_transforms() {
    input_file="$1"
    base_dir=$(dirname "$input_file")
    base_name=$(basename "$input_file")

    for feat in size dt tsam; do
        case "$base_name" in
            raw*.npz)
                output_name="${feat}${base_name#raw}"
                ;;
            *)
                output_name=$(echo "$base_name" | sed "s/raw/${feat}/")
                ;;
        esac

        output_file="${base_dir}/${output_name}"
        python exp/dataset_process/gen_transformed.py \
            --input_file "${input_file}" \
            -o "${output_file}" \
            -f "${feat}" \
            --seq_len="${seq_len}"
    done
}

root_dir="/data/exp/lxyu/Dataset/WF/Reproduce/features"

protocols=(vmess shadowsocks trojan)

seq_len=10000

for protocol in "${protocols[@]}"; do
    python exp/dataset_process/data_augmentation_netrand.py -i /data/exp/lxyu/Dataset/WF/Reproduce/features/${protocol}/raw.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/${protocol}/raw_netrand.npz

    gen_all_transforms ${root_dir}/${protocol}/raw_netrand.npz
done

wait