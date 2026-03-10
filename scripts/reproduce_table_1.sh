#! /bin/bash
# This script aims to reproduce Table 1 in this paper, with the prepared datasets.

# coverage=${1}
root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"

# Reproduce the first column, i.e., train with Normal + VMess, test with Shadowsocks and Trojan
# Load datasets
cp ${root_dir}/features/vmess/merge_size_bs_filter_strip_4.npz ${root_dir}/workspace/merge_size_bs_filter_strip.npz 
cp ${root_dir}/features/shadowsocks/size_bs_filter_strip_4.npz ${root_dir}/workspace/shadowsocks_size_bs_filter_strip.npz
cp ${root_dir}/features/trojan/size_bs_filter_strip_4.npz ${root_dir}/workspace/trojan_size_bs_filter_strip.npz
# TODO: Change feature name to size, currently they mean the same thing.
python exp/dataset_process/dataset_split.py -f direction --dataset ${root_dir}/workspace/merge_size_bs_filter_strip
python exp/dataset_process/dataset_split.py -f direction --dataset ${root_dir}/workspace/shadowsocks_size_bs_filter_strip
python exp/dataset_process/dataset_split.py -f direction --dataset ${root_dir}/workspace/trojan_size_bs_filter_strip

for i in {1..10}; do
    if [ -d "$root_dir/workspace/merge_size_bs_filter_strip/DF" ]; then
        rm -r "$root_dir/workspace/merge_size_bs_filter_strip/DF"
    fi

    ./scripts/DF.sh ${root_dir}/workspace/merge_size_bs_filter_strip cuda:0
    ./scripts/DF_test.sh ${root_dir}/workspace/merge_size_bs_filter_strip ${root_dir}/workspace/shadowsocks_size_bs_filter_strip cuda:0 
    ./scripts/DF_test.sh ${root_dir}/workspace/merge_size_bs_filter_strip ${root_dir}/workspace/trojan_size_bs_filter_strip cuda:0 
done

rm ${root_dir}/workspace/merge_size_bs_filter_strip.npz ${root_dir}/workspace/shadowsocks_size_bs_filter_strip.npz ${root_dir}/workspace/trojan_size_bs_filter_strip.npz
rm -r ${root_dir}/workspace/merge_size_bs_filter_strip ${root_dir}/workspace/shadowsocks_size_bs_filter_strip ${root_dir}/workspace/trojan_size_bs_filter_strip