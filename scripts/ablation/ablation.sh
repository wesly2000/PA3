#!/bin/bash

_pa3_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "${_pa3_script_dir}/_load_env.sh" ]]; then
    source "${_pa3_script_dir}/_load_env.sh"
else
    source "${_pa3_script_dir}/../_load_env.sh"
fi

# Leave-one-out ablation over Augmentation, Size Filter, and Strip.

root_dir="${PA3_REPO_ROOT}/Reproduce"
iter_num=8
coverage=4

protocols=(vmess shadowsocks trojan)

# Copy only when destination is missing; rm only when path exists.
copy_npz_if_missing() {
    local src=$1
    local dst=$2
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

# Each row: model|model_feature|split_feature|file_feature.
MODEL_CONFIGS=(
    "DF|size_bin|size|size"
)

    # "TikTok|dt|dt|dt"
    # "NetCLR|size_bin|size|size"
    # "RF|tsam|tsam|tsam"
    # "BAPM|size_bin|size|size"
    # "TF|size_bin|size|size"

protocol_workspace() {
    local protocol=$1
    local model_feature=$2
    local suffix=$3
    printf '%s/workspace/%s_%s_%s' "$root_dir" "$protocol" "$model_feature" "$suffix"
}

feature_file() {
    local protocol=$1
    local file_feature=$2
    local suffix=$3
    printf '%s/ablation/%s/%s_%s.npz' "$root_dir" "$protocol" "$file_feature" "$suffix"
}

other_protocols() {
    local train_protocol=$1
    local protocol
    for protocol in "${protocols[@]}"; do
        [ "$protocol" = "$train_protocol" ] && continue
        printf '%s\n' "$protocol"
    done
}

prepare_plain_dataset() {
    local protocol=$1
    local model_feature=$2
    local file_feature=$3
    local suffix=$4
    local workspace

    workspace=$(protocol_workspace "$protocol" "$model_feature" "$suffix")
    copy_npz_if_missing \
        "$(feature_file "$protocol" "$file_feature" "$suffix")" \
        "${workspace}.npz"
}

prepare_augmented_train_dataset() {
    local train_protocol=$1
    local model_feature=$2
    local file_feature=$3
    local base_suffix=$4
    local merged_suffix=$5
    local base_workspace merged_workspace test_protocol aug_workspace
    local merge_inputs=()

    base_workspace=$(protocol_workspace "$train_protocol" "$model_feature" "$base_suffix")
    merged_workspace=$(protocol_workspace "$train_protocol" "$model_feature" "$merged_suffix")

    copy_npz_if_missing \
        "$(feature_file "$train_protocol" "$file_feature" "$base_suffix")" \
        "${base_workspace}.npz"
    merge_inputs+=("${base_workspace}.npz")

    while IFS= read -r test_protocol; do
        aug_workspace=$(protocol_workspace "$train_protocol" "$model_feature" "${base_suffix}_aug_slope_${test_protocol}")
        copy_npz_if_missing \
            "$(feature_file "$train_protocol" "$file_feature" "${base_suffix}_aug_slope_${test_protocol}")" \
            "${aug_workspace}.npz"
        merge_inputs+=("${aug_workspace}.npz")
    done < <(other_protocols "$train_protocol")

    python exp/dataset_process/dataset_merge.py -i "${merge_inputs[@]}" -o "${merged_workspace}.npz"
}

split_dataset() {
    local split_feature=$1
    local dataset=$2
    python exp/dataset_process/dataset_split.py -f "$split_feature" --dataset "$dataset"
}

run_model_iteration() {
    local model=$1
    local train_workspace=$2
    local model_feature=$3
    local pretrain_workspace=$4
    shift 4
    local test_workspaces=("$@")
    local test_workspace

    rm_dir_if_exists "${train_workspace}/${model}"

    if [ "$model" = "NetCLR" ]; then
        ./scripts/${model}.sh "$train_workspace" "$model_feature" cuda:0 "$pretrain_workspace"
    else
        ./scripts/${model}.sh "$train_workspace" "$model_feature" cuda:0
    fi

    for test_workspace in "${test_workspaces[@]}"; do
        ./scripts/${model}_test.sh "$train_workspace" "$test_workspace" "$model_feature" cuda:0
    done
}

cleanup_dataset() {
    local dataset=$1
    rm_file_if_exists "${dataset}.npz"
    rm_dir_if_exists "$dataset"
}

run_ablation_case() {
    local case_name=$1
    local train_protocol=$2
    local model=$3
    local model_feature=$4
    local split_feature=$5
    local file_feature=$6
    local base_suffix=$7
    local train_suffix=$8
    local test_suffix=$9
    local uses_aug=${10}
    local train_workspace base_workspace pretrain_workspace test_protocol test_workspace
    local test_workspaces=()
    local cleanup_workspaces=()

    echo "Running ${case_name}: train=${train_protocol}, model=${model}"

    base_workspace=$(protocol_workspace "$train_protocol" "$model_feature" "$base_suffix")
    train_workspace=$(protocol_workspace "$train_protocol" "$model_feature" "$train_suffix")
    pretrain_workspace=None

    if [ "$uses_aug" = "1" ]; then
        prepare_augmented_train_dataset "$train_protocol" "$model_feature" "$file_feature" "$base_suffix" "$train_suffix"
        cleanup_workspaces+=("$base_workspace" "$train_workspace")
        while IFS= read -r test_protocol; do
            cleanup_workspaces+=("$(protocol_workspace "$train_protocol" "$model_feature" "${base_suffix}_aug_slope_${test_protocol}")")
        done < <(other_protocols "$train_protocol")
    else
        prepare_plain_dataset "$train_protocol" "$model_feature" "$file_feature" "$base_suffix"
        cleanup_workspaces+=("$train_workspace")
    fi

    split_dataset "$split_feature" "$train_workspace"
    if [ "$uses_aug" = "1" ]; then
        split_dataset "$split_feature" "$base_workspace"
        pretrain_workspace="$base_workspace"
    fi

    while IFS= read -r test_protocol; do
        test_workspace=$(protocol_workspace "$test_protocol" "$model_feature" "$test_suffix")
        prepare_plain_dataset "$test_protocol" "$model_feature" "$file_feature" "$test_suffix"
        split_dataset "$split_feature" "$test_workspace"
        test_workspaces+=("$test_workspace")
        cleanup_workspaces+=("$test_workspace")
    done < <(other_protocols "$train_protocol")

    for ((i=1; i<=iter_num; i++)); do
        run_model_iteration "$model" "$train_workspace" "$model_feature" "$pretrain_workspace" "${test_workspaces[@]}"
    done

    for workspace in "${cleanup_workspaces[@]}"; do
        cleanup_dataset "$workspace"
    done
}

for cfg_row in "${MODEL_CONFIGS[@]}"; do
    IFS='|' read -r model model_feature split_feature file_feature <<< "$cfg_row"

    for train_protocol in "${protocols[@]}"; do
        # Leave out Augmentation: Size Filter + Strip for both train and test.
        run_ablation_case \
            "no_aug" \
            "$train_protocol" \
            "$model" \
            "$model_feature" \
            "$split_feature" \
            "$file_feature" \
            "bs_filter_strip_${coverage}" \
            "bs_filter_strip_${coverage}" \
            "bs_filter_strip_${coverage}" \
            0

        # Leave out Size Filter: train with Strip + Augmentation, test with Strip.
        run_ablation_case \
            "no_size_filter" \
            "$train_protocol" \
            "$model" \
            "$model_feature" \
            "$split_feature" \
            "$file_feature" \
            "strip" \
            "strip_aug_slope" \
            "strip" \
            1

        # Leave out Strip: train with Size Filter + Augmentation, test with Size Filter.
        run_ablation_case \
            "no_strip" \
            "$train_protocol" \
            "$model" \
            "$model_feature" \
            "$split_feature" \
            "$file_feature" \
            "bs_filter_${coverage}" \
            "bs_filter_${coverage}_aug_slope" \
            "bs_filter_${coverage}" \
            1
    done
done
