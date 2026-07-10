#!/bin/bash
# set -x
root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"

# Example usage:
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw.npz
# Function to generate size, dt, tsam versions from raw .npz input.
# Replaces the leading "raw" in the basename (e.g. raw_bs_filter_4.npz -> size_bs_filter_4.npz).
gen_all_transforms() {
    input_file="$1"  # e.g., .../features/vmess/raw_bs_filter_4.npz
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
        python exp/dataset_process/gen_transformed.py --input_file "$input_file" -o "$output_file" -f "$feat" --seq_len="${seq_len:-10000}"
    done
}

vmess_coverage=4
shadowsocks_coverage=4
trojan_coverage=4

# VMess data transform
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_4_aug_noproxy.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_4_aug_no_cdf.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_4_aug_cdf.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_${vmess_coverage}.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${vmess_coverage}.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_slope_trojan.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks_gaussian.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_slope_trojan_gaussian.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_known_slope_trojan.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_known_slope_shadowsocks.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_${vmess_coverage}.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_${vmess_coverage}.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_trojan_gaussian.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_shadowsocks_gaussian.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip.npz

# # Shadowsocks data transform
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_${shadowsocks_coverage}.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${shadowsocks_coverage}.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_host_filter_strip.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${shadowsocks_coverage}_aug_slope_vmess.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${shadowsocks_coverage}_aug_slope_trojan.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${shadowsocks_coverage}_aug_slope_vmess_gaussian.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${shadowsocks_coverage}_aug_slope_trojan_gaussian.npz

# # Trojan data transform
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_${trojan_coverage}.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${trojan_coverage}.npz
gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_host_filter_strip.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${trojan_coverage}_aug_slope_shadowsocks.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${trojan_coverage}_aug_slope_vmess.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${trojan_coverage}_aug_slope_vmess_gaussian.npz
# gen_all_transforms /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${trojan_coverage}_aug_slope_shadowsocks_gaussian.npz