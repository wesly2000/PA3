#!/bin/bash

root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"
iter_num=5
device="cuda:0"
protocols=(vmess shadowsocks trojan)

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
NetCLR|size_bin|size|size
BAPM|size_bin|size|size
TF|size_bin|size|size
TikTok|dt|dt|dt
RF|tsam|tsam|tsam
'

workspace_path() {
    protocol=$1
    model_feature=$2
    suffix=$3

    if [ -n "$suffix" ]; then
        printf '%s/workspace/%s_%s_%s' "$root_dir" "$protocol" "$model_feature" "$suffix"
    else
        printf '%s/workspace/%s_%s' "$root_dir" "$protocol" "$model_feature"
    fi
}

feature_path() {
    protocol=$1
    file_feature=$2
    suffix=$3

    if [ -n "$suffix" ]; then
        printf '%s/features/%s/%s_%s.npz' "$root_dir" "$protocol" "$file_feature" "$suffix"
    else
        printf '%s/features/%s/%s.npz' "$root_dir" "$protocol" "$file_feature"
    fi
}

split_dataset() {
    workspace=$1
    split_feature=$2
    python exp/dataset_process/dataset_split.py -f "$split_feature" --dataset "$workspace"
}

prepare_protocol_datasets() {
    protocol=$1
    model_feature=$2
    split_feature=$3
    file_feature=$4

    base_workspace=$(workspace_path "$protocol" "$model_feature" "")

    copy_npz_if_missing "$(feature_path "$protocol" "$file_feature" "")" "${base_workspace}.npz"

    split_dataset "$base_workspace" "$split_feature"
}

other_protocols() {
    train_protocol=$1
    for protocol in "${protocols[@]}"; do
        [ "$protocol" = "$train_protocol" ] && continue
        printf '%s\n' "$protocol"
    done
}

run_train() {
    model=$1
    train_workspace=$2
    model_feature=$3
    pretrain_workspace=$4

    if [ "$model" = "NetCLR" ]; then
        ./scripts/${model}.sh "$train_workspace" "$model_feature" "$device" "$pretrain_workspace"
    else
        ./scripts/${model}.sh "$train_workspace" "$model_feature" "$device"
    fi
}

run_protocol_case() {
    model=$1
    model_feature=$2
    train_protocol=$3
    train_workspace=$(workspace_path "$train_protocol" "$model_feature" "")
    pretrain_workspace="$train_workspace"

    i=1
    while [ "$i" -le "$iter_num" ]; do
        # rm_dir_if_exists "${train_workspace}/${model}"

        run_train "$model" "$train_workspace" "$model_feature" "$pretrain_workspace"

        while IFS= read -r test_protocol; do
            test_workspace=$(workspace_path "$test_protocol" "$model_feature" "")
            ./scripts/${model}_test.sh "$train_workspace" "$test_workspace" "$model_feature" "$device"
        done < <(other_protocols "$train_protocol")

        i=$((i + 1))
    done
}

cleanup_protocol_datasets() {
    model_feature=$1
    for protocol in "${protocols[@]}"; do
        workspace=$(workspace_path "$protocol" "$model_feature" "")
        rm_file_if_exists "${workspace}.npz"
        rm_dir_if_exists "$workspace"
    done
}

printf '%s\n' "$MODEL_CONFIGS" | while IFS='|' read -r model model_feature split_feature file_feature; do
    [ -z "$model" ] && continue

    for protocol in "${protocols[@]}"; do
        prepare_protocol_datasets "$protocol" "$model_feature" "$split_feature" "$file_feature"
    done

    for train_protocol in "${protocols[@]}"; do
        run_protocol_case "$model" "$model_feature" "$train_protocol"
    done

    # cleanup_protocol_datasets "$model_feature"
done
