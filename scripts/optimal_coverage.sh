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
model=NetCLR
file_feature=size
split_feature=size
model_feature=size_bin
iter_num=3

coverages=(1 2 3 4 5 6 7 8 9)

# # VMess Strategy
# copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}.npz ${root_dir}/workspace/vmess_${model_feature}.npz 
# copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}.npz ${root_dir}/workspace/shadowsocks_${model_feature}.npz
# copy_npz_if_missing ${root_dir}/features/trojan/${file_feature}.npz ${root_dir}/workspace/trojan_${model_feature}.npz

# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}

# if [[ "${model}" = "NetCLR" ]]; then 
#     for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
#         if [ -d "${root_dir}/workspace/vmess_${model_feature}/${model}" ]; then
#             rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}/${model}"
#         fi

#         ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature} ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0 
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0 
#     done
# else 
#     for ((i=1; i<=iter_num; i++)); do
#         if [ -d "${root_dir}/workspace/vmess${model_feature}/${model}" ]; then
#             rm_dir_if_exists "${root_dir}/workspace/vmess${model_feature}/${model}"
#         fi

#         ./scripts/${model}.sh ${root_dir}/workspace/vmess${model_feature} ${model_feature} cuda:0
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess${model_feature} ${root_dir}/workspace/shadowsocks_${model_feature} ${model_feature} cuda:0 
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess${model_feature} ${root_dir}/workspace/trojan_${model_feature} ${model_feature} cuda:0 
#     done
# fi

# Size filter strategy (No strip)
# Loop through each coverage, train and test 10 times for each coverage
for coverage in "${coverages[@]}"; do
    copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_bs_filter_${coverage}.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}.npz
    copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_${coverage}.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}.npz
    copy_npz_if_missing ${root_dir}/features/trojan/${file_feature}_bs_filter_${coverage}.npz ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}.npz

    if [[ "${model}" = "NetCLR" ]]; then 
        python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}
        python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}
        python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}

        for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
            if [ -d "${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}/${model}" ]; then
                rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}/${model}"
            fi

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage} ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage} ${model_feature} cuda:0 
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage} ${model_feature} cuda:0 
        done

        rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}.npz
        rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}.npz
        rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}.npz 

        rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}
        rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}
        rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}
        
    else 
        python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}
        python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}
        python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}

        for ((i=1; i<=iter_num; i++)); do
            if [ -d "$root_dir/workspace/vmess_${model_feature}_bs_filter_$coverage/${model}" ]; then
                rm_dir_if_exists "$root_dir/workspace/vmess_${model_feature}_bs_filter_$coverage/${model}"
            fi

            ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage} ${model_feature} cuda:0
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage} ${model_feature} cuda:0 
            ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage} ${model_feature} cuda:0 
        done

        rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage}.npz 
        rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage}.npz 
        rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}.npz

        rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_${coverage} 
        rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_${coverage} 
        rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_${coverage}
    fi
done

# # Size filter strategy + Strip
# # Loop through each coverage, train and test 10 times for each coverage
# for coverage in "${coverages[@]}"; do
#     copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
#     copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
#     copy_npz_if_missing ${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz

#     if [[ "${model}" = "NetCLR" ]]; then 
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

#         for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
#             if [ -d "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}/${model}" ]; then
#                 rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}/${model}"
#             fi

#             ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#         done

#         rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
#         rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
#         rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz 

#         rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
#         rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
#         rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
        
#     else 
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

#         for ((i=1; i<=iter_num; i++)); do
#             if [ -d "$root_dir/workspace/vmess_${model_feature}_bs_filter_strip_$coverage/${model}" ]; then
#                 rm_dir_if_exists "$root_dir/workspace/vmess_${model_feature}_bs_filter_strip_$coverage/${model}"
#             fi

#             ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#         done

#         rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz 
#         rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz 
#         rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz

#         rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} 
#         rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} 
#         rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
#     fi
# done

# split_feature=size

# # Size filter strategy + Strip + Augmentation
# # Loop through each coverage, train and test 10 times for each coverage
# for coverage in "${coverages[@]}"; do
#     copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
#     copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz
#     copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz
#     copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
#     copy_npz_if_missing ${root_dir}/features/trojan/${file_feature}_bs_filter_strip_${coverage}.npz ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz

#     # Merge VMess datasets
#     python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py \
#     -i ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz \
#     ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz \
#     ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz \
#     -o ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope.npz

#     if [[ "${model}" = "NetCLR" ]]; then 
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

#         for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
#             if [ -d "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}/${model}" ]; then
#                 rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}/${model}"
#             fi

#             ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage} ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#         done

#         rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
#         rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz
#         rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz 

#         rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}
#         rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
#         rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
        
#     else 
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}
#         python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}

#         for ((i=1; i<=iter_num; i++)); do
#             if [ -d "$root_dir/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope/${model}" ]; then
#                 rm_dir_if_exists "$root_dir/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope/${model}"
#             fi

#             ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope ${model_feature} cuda:0
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#             ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage} ${model_feature} cuda:0 
#         done

#         rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}.npz
#         rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz 
#         rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz
#         rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope.npz 
#         rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage}.npz 
#         rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}.npz 

#         rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_bs_filter_strip_${coverage}_aug_slope 
#         rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_bs_filter_strip_${coverage} 
#         rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_bs_filter_strip_${coverage}
#     fi
# done

# split_feature=size
# # Host filter strategy + Strip + Augmentation
# copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_host_filter_strip.npz ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip.npz 
# copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_host_filter_strip_aug_slope_shadowsocks.npz ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_shadowsocks.npz
# copy_npz_if_missing ${root_dir}/features/vmess/${file_feature}_host_filter_strip_aug_slope_trojan.npz ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_trojan.npz
# copy_npz_if_missing ${root_dir}/features/shadowsocks/${file_feature}_host_filter_strip.npz ${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip.npz
# copy_npz_if_missing ${root_dir}/features/trojan/${file_feature}_host_filter_strip.npz ${root_dir}/workspace/trojan_${model_feature}_host_filter_strip.npz

# # Merge VMess datasets
# python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py -i ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip.npz ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_shadowsocks.npz ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_trojan.npz -o ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope.npz

# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip
# python exp/dataset_process/dataset_split.py -f ${split_feature} --dataset ${root_dir}/workspace/trojan_${model_feature}_host_filter_strip

# if [[ "${model}" = "NetCLR" ]]; then 
#     for ((i=1; i<=iter_num; i++)); do  # NetCLR requires pretraining
#         if [ -d "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope/${model}" ]; then
#             rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope/${model}"
#         fi

#         ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope ${model_feature} cuda:0 ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope ${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip ${model_feature} cuda:0 
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope ${root_dir}/workspace/trojan_${model_feature}_host_filter_strip ${model_feature} cuda:0 
#     done
# else 
#     for ((i=1; i<=iter_num; i++)); do
#         if [ -d "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope/${model}" ]; then
#             rm_dir_if_exists "${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope/${model}"
#         fi

#         ./scripts/${model}.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope ${model_feature} cuda:0
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope ${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip ${model_feature} cuda:0 
#         ./scripts/${model}_test.sh ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope ${root_dir}/workspace/trojan_${model_feature}_host_filter_strip ${model_feature} cuda:0 
#     done
# fi

# rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip.npz 
# rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope.npz 
# rm_file_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip.npz 
# rm_file_if_exists ${root_dir}/workspace/trojan_${model_feature}_host_filter_strip.npz 
# rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_shadowsocks.npz 
# rm_file_if_exists ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope_trojan.npz

# rm_dir_if_exists ${root_dir}/workspace/vmess_${model_feature}_host_filter_strip_aug_slope
# rm_dir_if_exists ${root_dir}/workspace/shadowsocks_${model_feature}_host_filter_strip
# rm_dir_if_exists ${root_dir}/workspace/trojan_${model_feature}_host_filter_strip