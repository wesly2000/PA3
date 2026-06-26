#!/bin/bash


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
# This script is used to reproduce the performance of DF under different coverages.
root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"
model=DF
file_feature=size
model_feature=size_bin
iter_num=8

# Coverage is fixed at 0.4
coverage=4

# Shadowsocks Strategy
split_feature=size
copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}.npz ${root_dir}/workspace/vmess_${model_feature}.npz 
copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}.npz ${root_dir}/workspace/shadowsocks_${model_feature}.npz
copy_npz_if_missing ${root_dir}/features/trojan/${file_feature}.npz ${root_dir}/workspace/trojan_${model_feature}.npz

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}

i=1
while [ "$i" -le "$iter_num" ]; do
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}/${model}"

    ./scripts/${model}.sh ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0
    ./scripts/${model}_test.sh ${root_dir}/workspace/shadowsocks_${model_feature} ${root_dir}/workspace/vmess_${model_feature} ${model_feature} cuda:0 
    ./scripts/${model}_test.sh ${root_dir}/workspace/shadowsocks_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0 
    i=$((i + 1))
done

# Size filter strategy (No strip)
# Loop through each coverage, train and test 10 times for each coverage
split_feature=direction
copy_npz_if_missing ${root_dir}/backup/vmess/${file_feature}_bs_filter_${coverage}.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}.npz
copy_npz_if_missing ${root_dir}/backup/shadowsocks/${file_feature}_bs_filter_${coverage}.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}.npz
copy_npz_if_missing ${root_dir}/backup/trojan/${file_feature}_bs_filter_${coverage}.npz ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}.npz

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}

i=1
while [ "$i" -le "$iter_num" ]; do
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}/${model}"

    ./scripts/${model}.sh ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage} ${model_feature} cuda:0
    ./scripts/${model}_test.sh ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage} ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage} ${model_feature} cuda:0 
    ./scripts/${model}_test.sh ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage} ${model_feature} cuda:0 
    i=$((i + 1))
done

rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}.npz 
rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}.npz 
rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}.npz

rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage} 
rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage} 
rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}


# Size filter strategy + Strip
# Loop through each coverage, train and test 10 times for each coverage
split_feature=size
copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
copy_npz_if_missing ${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

i=1
while [ "$i" -le "$iter_num" ]; do
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}/${model}"

    ./scripts/${model}.sh ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
    ./scripts/${model}_test.sh ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
    ./scripts/${model}_test.sh ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
    i=$((i + 1))
done

rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz 
rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz 
rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz

rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} 
rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} 
rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

# Size filter strategy + Strip + Augmentation
# Loop through each coverage, train and test 10 times for each coverage
split_feature=size
copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}_aug_slope_vmess.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope_vmess.npz
copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz
copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
copy_npz_if_missing ${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz

# Merge VMess datasets
python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py \
-i ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz \
${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope_vmess.npz \
${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz \
-o ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope.npz

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

i=1
while [ "$i" -le "$iter_num" ]; do
    rm_dir_if_exists "${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope/${model}"

    ./scripts/${model}.sh ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope ${model_feature} cuda:0
    ./scripts/${model}_test.sh ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
    ./scripts/${model}_test.sh ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
    i=$((i + 1))
done

rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope_vmess.npz 
rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz
rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope.npz 
rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz 
rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz 

rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}_aug_slope 
rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} 
rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}