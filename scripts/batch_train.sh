#!/bin/bash

# coverage=${1}
# root_dir="/data/exp/lxyu/Dataset/WF/datasets"
root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"
file_feature=dt
split_feature=dt
model_feature=dt
# model=AWF
model=TikTok

coverages=(4)

# Normal Strategy
cp ${root_dir}/features/normal/${file_feature}.npz ${root_dir}/workspace/normal_${model_feature}.npz 
cp ${root_dir}/features/vmess/${file_feature}.npz ${root_dir}/workspace/vmess_${model_feature}.npz 
cp ${root_dir}/features/shadowsocks/${file_feature}.npz ${root_dir}/workspace/shadowsocks_${model_feature}.npz
cp ${root_dir}/features/trojan/${file_feature}.npz ${root_dir}/workspace/trojan_${model_feature}.npz

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/normal_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}

if [[ "${model}" = "NetCLR" ]]; then 
    for i in {1..8}; do  # NetCLR requires pretraining
        if [ -d "${root_dir}/workspace/normal_${model_feature}/${model}" ]; then
            rm -r "${root_dir}/workspace/normal_${model_feature}/${model}"
        fi

        ./scripts/${model}.sh ${root_dir}/workspace/normal_${model_feature} ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}
        ./scripts/${model}_test.sh ${root_dir}/workspace/normal_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0 
        ./scripts/${model}_test.sh ${root_dir}/workspace/normal_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0 
    done
else 
    for i in {1..1}; do
        if [ -d "${root_dir}/workspace/normal_${model_feature}/${model}" ]; then
            rm -r "${root_dir}/workspace/normal_${model_feature}/${model}"
        fi

        ./scripts/${model}.sh ${root_dir}/workspace/normal_${model_feature} ${model_feature} cuda:0
        ./scripts/${model}_test.sh ${root_dir}/workspace/normal_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0 
        ./scripts/${model}_test.sh ${root_dir}/workspace/normal_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0 
    done
fi

# Mix Strategy
python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/normal_${model_feature}.npz  ${root_dir}/workspace/vmess_${model_feature}.npz -o ${root_dir}/workspace/merge_${model_feature}.npz 

python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}
python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}

if [[ "${model}" = "NetCLR" ]]; then 
    for i in {1..8}; do  # NetCLR requires pretraining
        if [ -d "${root_dir}/workspace/vmess_${model_feature}/${model}" ]; then
            rm -r "${root_dir}/workspace/vmess_${model_feature}/${model}"
        fi

        ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature} ${model_feature} cuda:0 ${root_dir}/workspace/normal_${model_feature}
        ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0 
        ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0 
    done
else
    for i in {1..1}; do
        if [ -d "${root_dir}/workspace/merge_${model_feature}/${model}" ]; then
            rm -r "${root_dir}/workspace/merge_${model_feature}/${model}"
        fi

        ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature} ${model_feature} cuda:0
        ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0 
        ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0 
    done 
fi


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
# cp ${root_dir}/features/normal/${file_feature}.npz ${root_dir}/workspace/normal_${model_feature}_strip.npz 
# cp ${root_dir}/features/vmess/${file_feature}_strip.npz ${root_dir}/workspace/vmess_${model_feature}_strip.npz 
# cp ${root_dir}/features/shadowsocks/${file_feature}_strip.npz ${root_dir}/workspace/shadowsocks_${model_feature}_strip.npz
# cp ${root_dir}/features/trojan/${file_feature}_strip.npz ${root_dir}/workspace/trojan_${model_feature}_strip.npz

# if [[ "${model}" = "NetCLR" ]]; then 

#     python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/normal_${model_feature}_strip
#     python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_strip
#     python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_strip
#     python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_strip

#     for i in {1..9}; do  # NetCLR requires pretraining
#         if [ -d "${root_dir}/workspace/vmess_${model_feature}_strip/${model}" ]; then
#             rm -r "${root_dir}/workspace/vmess_${model_feature}_strip/${model}"
#         fi

#         ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_strip ${model_feature} cuda:0 ${root_dir}/workspace/normal_${model_feature}_strip
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_strip ${root_dir}/workspace/shadowsocks_${model_feature}_strip ${model_feature} cuda:0 
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_strip ${root_dir}/workspace/trojan_${model_feature}_strip ${model_feature} cuda:0 
#     done

#     rm ${root_dir}/workspace/normal_${model_feature}_strip.npz 
#     rm ${root_dir}/workspace/vmess_${model_feature}_strip.npz
#     rm ${root_dir}/workspace/shadowsocks_${model_feature}_strip.npz
#     rm ${root_dir}/workspace/trojan_${model_feature}_strip.npz 

#     rm -r ${root_dir}/workspace/normal_${model_feature}_strip
#     rm -r ${root_dir}/workspace/vmess_${model_feature}_strip
#     rm -r ${root_dir}/workspace/shadowsocks_${model_feature}_strip
#     rm -r ${root_dir}/workspace/trojan_${model_feature}_strip
    
# else 
#     python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/normal_${model_feature}_strip.npz  ${root_dir}/workspace/vmess_${model_feature}_strip.npz -o ${root_dir}/workspace/merge_${model_feature}_strip.npz 

#     python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_strip
#     python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_strip
#     python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}_strip

#     for i in {1..3}; do
#         if [ -d "${root_dir}/workspace/merge_${model_feature}_strip/${model}" ]; then
#             rm -r "${root_dir}/workspace/merge_${model_feature}_strip/${model}"
#         fi

#         ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature}_strip ${model_feature} cuda:0
#         ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_strip ${root_dir}/workspace/shadowsocks_${model_feature}_strip ${model_feature} cuda:0 
#         ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_strip ${root_dir}/workspace/trojan_${model_feature}_strip ${model_feature} cuda:0 
#     done

#     rm ${root_dir}/workspace/normal_${model_feature}_strip.npz 
#     rm ${root_dir}/workspace/vmess_${model_feature}_strip.npz
#     rm ${root_dir}/workspace/shadowsocks_${model_feature}_strip.npz
#     rm ${root_dir}/workspace/trojan_${model_feature}_strip.npz 
#     rm ${root_dir}/workspace/merge_${model_feature}_strip.npz 

#     rm -r ${root_dir}/workspace/shadowsocks_${model_feature}_strip
#     rm -r ${root_dir}/workspace/trojan_${model_feature}_strip
#     rm -r ${root_dir}/workspace/merge_${model_feature}_strip
# fi


# # Loop through each coverage, train and test 10 times for each coverage
# for coverage in "${coverages[@]}"; do
#     cp ${root_dir}/features/normal/${file_feature}_bs_filter_strip.npz ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip.npz 
#     cp ${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz 
#     cp ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverages}.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
#     cp ${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz 

#     if [[ "${model}" = "NetCLR" ]]; then 
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

#         for i in {1..5}; do  # NetCLR requires pretraining
#             if [ -d "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}/${model}" ]; then
#                 rm -r "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}/${model}"
#             fi

#             ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#         done

#         rm ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip.npz 
#         rm ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
#         rm ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
#         rm ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz 

#         rm -r ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip
#         rm -r ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
#         rm -r ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
#         rm -r ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
        
#     else 
#         python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz -o ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}.npz

#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

#         for i in {1..3}; do
#             if [ -d "$root_dir/workspace/merge_${model_feature}_bs_filter_strip_$coverage/${model}" ]; then
#                 rm -r "$root_dir/workspace/merge_${model_feature}_bs_filter_strip_$coverage/${model}"
#             fi

#             ./scripts/${model}.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
#             ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#             ./scripts/${model}_test.sh ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#         done

#         rm ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage}.npz 
#         rm ${root_dir}/workspace/normal_${model_feature}_bs_filter_strip.npz
#         rm ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
#         rm ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz 
#         rm ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz

#         rm -r ${root_dir}/workspace/merge_${model_feature}_bs_filter_strip_${coverage} 
#         rm -r ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} 
#         rm -r ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
#     fi
# done