#! /bin/bash

coverage=${1}

# python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/merge_dir_bs_filter_strip_${coverage}
# python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/vmess_dir_bs_filter_strip_${coverage}
# python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/trojan_dir_bs_filter_strip_${coverage}

# python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/merge_dir
# python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/vmess_dir
python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/merge_dir_strip

# python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/normal_dir
# python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/vmess_dir
# python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/shadowsocks_dir
# python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/trojan_dir