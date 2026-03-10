#!/bin/bash

root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"

# ARES + MTAF
# file_feature=mtaf
# split_feature=mtaf
# model_feature=mtaf
# model=ARES
# BAPM + size
# file_feature=size
# split_feature=size
# model_feature=size_bin
# model=BAPM
# AWF + size_bin
# file_feature=tsam
# split_feature=tsam
# model_feature=tsam
# model=NetCLR
# Best coverage
# TF=4, DF=4, RF=4
# TikTok + dt
# file_feature=dt
# split_feature=dt
# model_feature=dt
# model=TikTok
# VarCNN + dt2
# file_feature=dt_shifted
# split_feature=dt
# model_feature=dt2
# model=VarCNN
# TF + size
file_feature=size
split_feature=size
model_feature=size_bin
model=TF
# RF + TSAM
# file_feature=tsam
# split_feature=tsam
# model_feature=tsam
# model=RF

# Normal Strategy
cp ${root_dir}/features/normal/${file_feature}.npz ${root_dir}/workspace/normal_${model_feature}.npz 
cp ${root_dir}/features/vmess/${file_feature}.npz ${root_dir}/workspace/vmess_${model_feature}.npz 
cp ${root_dir}/features/shadowsocks/${file_feature}.npz ${root_dir}/workspace/shadowsocks_${model_feature}.npz
cp ${root_dir}/features/trojan/${file_feature}.npz ${root_dir}/workspace/trojan_${model_feature}.npz

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/normal_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}

for i in {1..8}; do
    if [ -d "${root_dir}/workspace/normal_${model_feature}/${model}" ]; then
        rm -r "${root_dir}/workspace/normal_${model_feature}/${model}"
    fi

    ./scripts/${model}.sh ${root_dir}/workspace/normal_${model_feature} ${model_feature} cuda:0
    ./scripts/${model}_test.sh ${root_dir}/workspace/normal_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0 
    ./scripts/${model}_test.sh ${root_dir}/workspace/normal_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0 
done

# Mix Strategy
python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/normal_${model_feature}.npz  ${root_dir}/workspace/vmess_${model_feature}.npz -o ${root_dir}/workspace/merge_${model_feature}.npz 

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}

for i in {1..7}; do
    if [ -d "${root_dir}/workspace/merge_${model_feature}/${model}" ]; then
        rm -r "${root_dir}/workspace/merge_${model_feature}/${model}"
    fi

    ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature} ${model_feature} cuda:0
    ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0 
    ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0 
done

rm ${root_dir}/workspace/normal_${model_feature}.npz 
rm ${root_dir}/workspace/vmess_${model_feature}.npz
rm ${root_dir}/workspace/shadowsocks_${model_feature}.npz
rm ${root_dir}/workspace/trojan_${model_feature}.npz 
rm ${root_dir}/workspace/merge_${model_feature}.npz 

rm -r ${root_dir}/workspace/normal_${model_feature}
rm -r ${root_dir}/workspace/vmess_${model_feature}
rm -r ${root_dir}/workspace/shadowsocks_${model_feature}
rm -r ${root_dir}/workspace/trojan_${model_feature}
rm -r ${root_dir}/workspace/merge_${model_feature}

# Mix + Strip Strategy
# Note that Normal does not require stripping
cp ${root_dir}/features/normal/${file_feature}.npz ${root_dir}/workspace/normal_${model_feature}_strip.npz 
cp ${root_dir}/features/vmess/${file_feature}_strip.npz ${root_dir}/workspace/vmess_${model_feature}_strip.npz 
cp ${root_dir}/features/shadowsocks/${file_feature}_strip.npz ${root_dir}/workspace/shadowsocks_${model_feature}_strip.npz
cp ${root_dir}/features/trojan/${file_feature}_strip.npz ${root_dir}/workspace/trojan_${model_feature}_strip.npz

python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/normal_${model_feature}_strip.npz  ${root_dir}/workspace/vmess_${model_feature}_strip.npz -o ${root_dir}/workspace/merge_${model_feature}_strip.npz 

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_strip
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_strip
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}_strip

for i in {1..7}; do
    if [ -d "${root_dir}/workspace/merge_${model_feature}_strip/${model}" ]; then
        rm -r "${root_dir}/workspace/merge_${model_feature}_strip/${model}"
    fi

    ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature}_strip ${model_feature} cuda:0
    ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_strip ${root_dir}/workspace/shadowsocks_${model_feature}_strip ${model_feature} cuda:0 
    ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_strip ${root_dir}/workspace/trojan_${model_feature}_strip ${model_feature} cuda:0 
done

rm ${root_dir}/workspace/normal_${model_feature}_strip.npz 
rm ${root_dir}/workspace/vmess_${model_feature}_strip.npz
rm ${root_dir}/workspace/shadowsocks_${model_feature}_strip.npz
rm ${root_dir}/workspace/trojan_${model_feature}_strip.npz 
rm ${root_dir}/workspace/merge_${model_feature}_strip.npz 

rm -r ${root_dir}/workspace/shadowsocks_${model_feature}_strip
rm -r ${root_dir}/workspace/trojan_${model_feature}_strip
rm -r ${root_dir}/workspace/merge_${model_feature}_strip

# Mix + Strip + Size Filter Strategy
coverage=7

cp ${root_dir}/features/normal/${file_feature}_bs_filter_strip.npz ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip.npz 
cp ${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz 
cp ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
cp ${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz 

python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz -o ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}.npz

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

for i in {1..7}; do
    if [ -d "$root_dir/workspace/merge_${model_feature}_bs_filter_strip_$coverage/${model}" ]; then
        rm -r "$root_dir/workspace/merge_${model_feature}_bs_filter_strip_$coverage/${model}"
    fi

    ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
    ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
    ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
done

rm ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}.npz 
rm ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip.npz
rm ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
rm ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz 
rm ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz

rm -r ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} 
rm -r ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} 
rm -r ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}