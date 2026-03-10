#!/bin/bash

root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"

# We do not retrain augmentation model (RF here). Instead, we only retrain Holmes itself.
model=Holmes
model_feature=dt
file_feature=dt
split_feature=dt

# Unproxied Strategy
# cp ${root_dir}/features/normal/${file_feature}.npz ${root_dir}/workspace/normal_${model_feature}.npz 
# cp ${root_dir}/features/vmess/${file_feature}.npz ${root_dir}/workspace/vmess_${model_feature}.npz 
# cp ${root_dir}/features/shadowsocks/${file_feature}.npz ${root_dir}/workspace/shadowsocks_${model_feature}.npz
# cp ${root_dir}/features/trojan/${file_feature}.npz ${root_dir}/workspace/trojan_${model_feature}.npz

# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/normal_${model_feature}
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}

# # Generate early traffic with different loading ratio
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/normal_${model_feature}
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/vmess_${model_feature}
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/shadowsocks_${model_feature}
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/trojan_${model_feature}

# start=100
# end=100
# step=10
# for ((percent=start; percent<=end; percent+=step));
# do
#     python exp/dataset_process/gen_taf.py --dataset ${root_dir}/workspace/shadowsocks_${model_feature} --seq_len 10000 --in_file test_p${percent}
#     python exp/dataset_process/gen_taf.py --dataset ${root_dir}/workspace/trojan_${model_feature} --seq_len 10000 --in_file test_p${percent}
# done

# for i in {1..1}; do
#     if [ -d "${root_dir}/workspace/normal_${model_feature}/${model}" ]; then
#         rm -r "${root_dir}/workspace/normal_${model_feature}/${model}"
#     fi

#     ./scripts/${model}.sh ${root_dir}/workspace/normal_${model_feature} cuda:0
#     ./scripts/${model}_test.sh ${root_dir}/workspace/normal_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} cuda:0 
#     ./scripts/${model}_test.sh ${root_dir}/workspace/normal_${model_feature} ${root_dir}/workspace/trojan_${model_feature} cuda:0 
# done

# Mix Strategy
# python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/normal_${model_feature}.npz  ${root_dir}/workspace/vmess_${model_feature}.npz -o ${root_dir}/workspace/merge_${model_feature}.npz 
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}

# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/merge_${model_feature}

# for i in {1..1}; do
#     if [ -d "${root_dir}/workspace/merge_${model_feature}/${model}" ]; then
#         rm -r "${root_dir}/workspace/merge_${model_feature}/${model}"
#     fi

#     ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature} cuda:0
#     ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} cuda:0 
#     ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature} ${root_dir}/workspace/trojan_${model_feature} cuda:0 
# done

# Mix + Strip
# cp ${root_dir}/features/normal/${file_feature}.npz ${root_dir}/workspace/normal_${model_feature}_strip.npz 
# cp ${root_dir}/features/vmess/${file_feature}_strip.npz ${root_dir}/workspace/vmess_${model_feature}_strip.npz 
# cp ${root_dir}/features/shadowsocks/${file_feature}_strip.npz ${root_dir}/workspace/shadowsocks_${model_feature}_strip.npz
# cp ${root_dir}/features/trojan/${file_feature}_strip.npz ${root_dir}/workspace/trojan_${model_feature}_strip.npz

# python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/normal_${model_feature}_strip.npz  ${root_dir}/workspace/vmess_${model_feature}_strip.npz -o ${root_dir}/workspace/merge_${model_feature}_strip.npz 

# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_strip
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_strip
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}_strip

# # Generate early traffic with different loading ratio
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/shadowsocks_${model_feature}_strip
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/trojan_${model_feature}_strip
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/merge_${model_feature}_strip

# start=100
# end=100
# step=10
# for ((percent=start; percent<=end; percent+=step));
# do
#     python exp/dataset_process/gen_taf.py --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_strip --seq_len 10000 --in_file test_p${percent}
#     python exp/dataset_process/gen_taf.py --dataset ${root_dir}/workspace/trojan_${model_feature}_strip --seq_len 10000 --in_file test_p${percent}
# done

# for i in {1..1}; do
#     if [ -d "${root_dir}/workspace/merge_${model_feature}_strip/${model}" ]; then
#         rm -r "${root_dir}/workspace/merge_${model_feature}_strip/${model}"
#     fi

#     ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature}_strip cuda:0
#     ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_strip ${root_dir}/workspace/shadowsocks_${model_feature}_strip cuda:0 
#     ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_strip ${root_dir}/workspace/trojan_${model_feature}_strip cuda:0 
# done

# Mix + Strip + Size Filter
# coverage=4
# cp ${root_dir}/features/normal/${file_feature}_bs_filter_strip.npz ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip.npz 
# cp ${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz 
# cp ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
# cp ${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz

# python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip.npz  ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz -o ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}.npz 

# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}

# # Generate early traffic with different loading ratio
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
# python exp/dataset_process/gen_early_traffic.py --dataset /data/exp/lxyu/Dataset/WF/Reproduce/workspace/merge_${model_feature}_bs_filter_strip_${coverage}

# start=100
# end=100
# step=10
# for ((percent=start; percent<=end; percent+=step));
# do
#     python exp/dataset_process/gen_taf.py --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} --seq_len 10000 --in_file test_p${percent}
#     python exp/dataset_process/gen_taf.py --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} --seq_len 10000 --in_file test_p${percent}
# done

# for i in {1..1}; do
#     if [ -d "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}/${model}" ]; then
#         rm -r "${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}/${model}"
#     fi

#     ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} cuda:0
#     ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} cuda:0 
#     ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} cuda:0 
# done