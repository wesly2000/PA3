#!/bin/bash

_pa3_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_pa3_script_dir}/_load_env.sh" ]]; then
    source "${_pa3_script_dir}/_load_env.sh"
else
    source "${_pa3_script_dir}/../_load_env.sh"
fi

seq_len=10000

# Example usage:
# gen_all_transforms ${PA3_REPO_ROOT}/Reproduce/features/vmess/raw.npz
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

root_dir="${PA3_REPO_ROOT}/Reproduce/features"

python exp/data_extract/csv_batch_extract.py -d ${PA3_REPO_ROOT}/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/vmess/raw_rosetta.npz --rosetta --feature raw

python exp/data_extract/csv_batch_extract.py -d ${PA3_REPO_ROOT}/VisualSeg/csv_db_extract -p shadowsocks -o ${root_dir}/shadowsocks/raw_rosetta.npz --rosetta --feature raw

python exp/data_extract/csv_batch_extract.py -d ${PA3_REPO_ROOT}/VisualSeg/csv_db_extract -p trojan -o ${root_dir}/trojan/raw_rosetta.npz --rosetta --feature raw

gen_all_transforms ${root_dir}/vmess/raw_rosetta.npz

gen_all_transforms ${root_dir}/shadowsocks/raw_rosetta.npz

gen_all_transforms ${root_dir}/trojan/raw_rosetta.npz

wait
