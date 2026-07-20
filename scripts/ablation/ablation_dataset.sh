#!/bin/bash

_pa3_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_pa3_script_dir}/_load_env.sh" ]]; then
    source "${_pa3_script_dir}/_load_env.sh"
else
    source "${_pa3_script_dir}/../_load_env.sh"
fi
# set -x

root_dir="${PA3_REPO_ROOT}/Reproduce"
csv_dir="${PA3_REPO_ROOT}/VisualSeg/csv_db_extract"

coverage=0.4
coverage_tag=4
seq_len=10000

protocols=(vmess shadowsocks trojan)

extract_raw() {
    protocol="$1"
    output_file="$2"
    shift 2

    python exp/data_extract/csv_batch_extract.py \
        -d "${csv_dir}" \
        -p "${protocol}" \
        -o "${output_file}" \
        --feature raw \
        "$@"
}

# Generate size, dt, and tsam versions from a raw .npz input.
# Only the leading "raw" is replaced, preserving the ablation suffix.
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
            --seq_len="${seq_len}" &
    done
}

for train_protocol in "${protocols[@]}"; do
    feature_dir="${root_dir}/ablation/${train_protocol}"

    # Leave out Augmentation: Size Filter + Strip.
    raw_no_aug="${feature_dir}/raw_bs_filter_strip_${coverage_tag}.npz"
    extract_raw "${train_protocol}" "${raw_no_aug}" \
        --bs_filter \
        --coverage "${coverage}" \
        --strip
    gen_all_transforms "${raw_no_aug}"

    # Leave out Size Filter: Strip + Augmentation.
    raw_no_size_filter="${feature_dir}/raw_strip.npz"
    extract_raw "${train_protocol}" "${raw_no_size_filter}" \
        --strip
    gen_all_transforms "${raw_no_size_filter}"

    # Leave out Strip: Size Filter + Augmentation.
    raw_no_strip="${feature_dir}/raw_bs_filter_${coverage_tag}.npz"
    extract_raw "${train_protocol}" "${raw_no_strip}" \
        --bs_filter \
        --coverage "${coverage}"
    gen_all_transforms "${raw_no_strip}"

    for test_protocol in "${protocols[@]}"; do
        [ "${test_protocol}" = "${train_protocol}" ] && continue

        raw_no_size_filter_aug="${feature_dir}/raw_strip_aug_slope_${test_protocol}.npz"
        extract_raw "${train_protocol}" "${raw_no_size_filter_aug}" \
            --strip \
            --slope "${test_protocol}"
        gen_all_transforms "${raw_no_size_filter_aug}"

        raw_no_strip_aug="${feature_dir}/raw_bs_filter_${coverage_tag}_aug_slope_${test_protocol}.npz"
        extract_raw "${train_protocol}" "${raw_no_strip_aug}" \
            --bs_filter \
            --coverage "${coverage}" \
            --slope "${test_protocol}"
        gen_all_transforms "${raw_no_strip_aug}"
    done
done

wait
