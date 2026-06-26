#!/bin/bash
# set -x
root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"

coverages=(4)
seq_len=10000

# VMess Size Filter only
# for coverage in "${coverages[@]}"; do
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_${coverage}.npz --bs_filter --coverage .${coverage} --feature raw &
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_${coverage}.npz --bs_filter --coverage .${coverage} --feature raw &
# done

# VMess Size Filter + Strip
# for coverage in "${coverages[@]}"; do
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_${coverage}.npz --bs_filter --coverage .${coverage} --feature raw &
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_${coverage}.npz --bs_filter --coverage .${coverage} --feature raw &
# done

# for coverage in "${coverages[@]}"; do
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_4.npz --bs_filter --strip --feature raw &
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_4.npz --bs_filter --strip --feature raw &
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_4.npz --bs_filter --strip --feature raw &
# done


# for coverage in "${coverages[@]}"; do
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/size_bs_filter_${coverage}.npz -f size --seq_len=10000 &
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/size_bs_filter_${coverage}.npz -f size --seq_len=10000 &
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/size_bs_filter_${coverage}.npz -f size --seq_len=10000 &
# done

# # Size Filter + Strip
# feature=tsam
# for coverage in "${coverages[@]}"; do
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/${feature}_bs_filter_strip_${coverage}.npz -f ${feature} --seq_len=10000 &
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/${feature}_bs_filter_strip_${coverage}.npz -f ${feature} --seq_len=10000 &
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/${feature}_bs_filter_strip_${coverage}.npz -f ${feature} --seq_len=10000 &
# done


# VMess Size Filter + Strip + Augmentation
# for coverage in "${coverages[@]}"; do
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/backup/vmess/raw_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz --bs_filter --coverage .${coverage} --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/shadowsocks_vmess_slope_ratio.npz --feature ${feature} &
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/backup/vmess/raw_bs_filter_strip_${coverage}_aug_slope_trojan.npz --bs_filter --coverage .${coverage} --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/trojan_vmess_slope_ratio.npz --feature ${feature} &
# done

# # Size Filter + Strip + Augmentation (For Trojan and Shadowsocks)
coverage=4
# ## Raw data extraction
# feature=raw
# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${coverage}_aug_slope_vmess.npz --bs_filter --coverage .${coverage} --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/vmess_shadowsocks_slope_ratio.npz --feature ${feature} &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${coverage}_aug_slope_trojan.npz --bs_filter --coverage .${coverage} --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/trojan_shadowsocks_slope_ratio.npz --feature ${feature} &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${coverage}_aug_slope_vmess.npz --bs_filter --coverage .${coverage} --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/vmess_trojan_slope_ratio.npz --feature ${feature} &

# python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz --bs_filter --coverage .${coverage} --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/shadowsocks_trojan_slope_ratio.npz --feature ${feature} 

# ## Data transformation
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${coverage}_aug_slope_vmess.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/size_bs_filter_strip_${coverage}_aug_slope_vmess.npz -f size --seq_len=10000 &
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${coverage}_aug_slope_trojan.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/size_bs_filter_strip_${coverage}_aug_slope_trojan.npz -f size --seq_len=10000 &
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${coverage}_aug_slope_vmess.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/size_bs_filter_strip_${coverage}_aug_slope_vmess.npz -f size --seq_len=10000 &
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/size_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz -f size --seq_len=10000 &

# Host Filter + Strip + Augmentation
## Raw data extraction

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_trojan.npz -f exp/data_extract/filter.txt --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/trojan_vmess_slope_ratio.npz --feature raw &
# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_shadowsocks.npz -f exp/data_extract/filter.txt --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/shadowsocks_vmess_slope_ratio.npz --feature raw &
# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_host_filter_strip.npz -f exp/data_extract/filter.txt --strip --feature raw &
# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_host_filter_strip.npz -f exp/data_extract/filter.txt --strip --feature raw &

## Data transformation

# feature=dt
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_shadowsocks.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/${feature}_host_filter_strip_aug_slope_shadowsocks.npz -f ${feature} --seq_len=10000 &
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_trojan.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/${feature}_host_filter_strip_aug_slope_trojan.npz -f ${feature} --seq_len=10000 &
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_host_filter_strip.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/${feature}_host_filter_strip.npz -f ${feature} --seq_len=10000 &
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_host_filter_strip.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/${feature}_host_filter_strip.npz -f ${feature} --seq_len=10000 &

# feature=tsam
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_shadowsocks.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/${feature}_host_filter_strip_aug_slope_shadowsocks.npz -f ${feature} --seq_len=10000 &
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_trojan.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/${feature}_host_filter_strip_aug_slope_trojan.npz -f ${feature} --seq_len=10000 &
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_host_filter_strip.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/${feature}_host_filter_strip.npz -f ${feature} --seq_len=10000 &
# nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_host_filter_strip.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/${feature}_host_filter_strip.npz -f ${feature} --seq_len=10000 &



# for coverage in "${coverages[@]}"; do
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/backup/vmess/raw_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/backup/vmess/size_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz -f size --seq_len=10000 &
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/backup/vmess/raw_bs_filter_strip_${coverage}_aug_slope_trojan.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/backup/vmess/size_bs_filter_strip_${coverage}_aug_slope_trojan.npz -f size --seq_len=10000 &
# done

# for coverage in "${coverages[@]}"; do
#     python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/${feature}_bs_filter_strip_${coverage}.npz -f ${feature} --seq_len=${seq_len}
#     python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/${feature}_bs_filter_strip_${coverage}.npz -f ${feature} --seq_len=${seq_len}
#     python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/${feature}_bs_filter_strip_${coverage}.npz -f ${feature} --seq_len=${seq_len}
# done

# for coverage in "${coverages[@]}"; do
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/${feature}_bs_filter_strip_${coverage}_aug_slope_shadowsocks.npz -f ${feature} --seq_len=${seq_len} &
#     nohup python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${coverage}_aug_slope_trojan.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/${feature}_bs_filter_strip_${coverage}_aug_slope_trojan.npz -f ${feature} --seq_len=${seq_len} &
# done

# python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/normal/raw.npz -o ${root_dir}/features/normal/${feature}.npz -f ${feature} --seq_len=${seq_len}
# python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/vmess/raw.npz -o ${root_dir}/features/vmess/${feature}.npz -f ${feature} --seq_len=${seq_len}
# python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/shadowsocks/raw.npz -o ${root_dir}/features/shadowsocks/${feature}.npz -f ${feature} --seq_len=${seq_len}
# python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/trojan/raw.npz -o ${root_dir}/features/trojan/${feature}.npz -f ${feature} --seq_len=${seq_len}


# for coverage in "${coverages[@]}"; do
    # nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/datasets/vmess_dir_bs_filter_strip.npz  --strip  &

    # nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o /data/exp/lxyu/Dataset/WF/datasets/shadowsocks_dir_bs_filter_strip.npz --strip  &

    # nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o /data/exp/lxyu/Dataset/WF/datasets/trojan_dir_bs_filter_strip.npz --strip  &

    # python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p normal -o /data/exp/lxyu/Dataset/WF/datasets/normal_dir_bs_filter_strip.npz --strip 

    # python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py --coverage ${coverage}
    # python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py

    # python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/merge_dir_strip
    # python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/vmess_dir_bs_filter_strip_${coverage}
    # python exp/dataset_process/dataset_split.py -f direction --dataset /data/exp/lxyu/Dataset/WF/datasets/shadowsocks_dir_bs_filter_strip_${coverage}
# done

# for coverage in "${coverages[@]}"; do
#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/datasets/vmess_dir.npz    &

#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o /data/exp/lxyu/Dataset/WF/datasets/shadowsocks_dir.npz   &

#     nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o /data/exp/lxyu/Dataset/WF/datasets/trojan_dir.npz   &

#     python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p normal -o /data/exp/lxyu/Dataset/WF/datasets/normal_dir.npz  

#     python /home/lxyu/Reproduction/WFLib/exp/dataset_process/dataset_merge.py

#     ./scripts/split.sh ${coverage}
# done

# for coverage in "${coverages[@]}"; do
#     python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess --feature raw -o ${root_dir}/features/vmess/raw_bs_filter_strip_${coverage}.npz --bs_filter --coverage .${coverage} --strip 
#     python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan --feature raw -o ${root_dir}/features/trojan/raw_bs_filter_strip_${coverage}.npz --bs_filter --coverage .${coverage} --strip 
#     python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks --feature raw -o ${root_dir}/features/shadowsocks/raw_bs_filter_strip_${coverage}.npz --bs_filter --coverage .${coverage} --strip 
# done

# Obtain TSAM datasets
# nohup python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/normal/raw_bs_filter_strip.npz -o ${root_dir}/features/normal/tsam_bs_filter_strip.npz -f tsam &
# for coverage in "${coverages[@]}"; do
#     nohup python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/vmess/raw_bs_filter_strip_${coverage}.npz -o ${root_dir}/features/vmess/tsam_bs_filter_strip_${coverage}.npz -f tsam &
#     nohup python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/shadowsocks/raw_bs_filter_strip_${coverage}.npz -o ${root_dir}/features/shadowsocks/tsam_bs_filter_strip_${coverage}.npz -f tsam &
#     python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/trojan/raw_bs_filter_strip_${coverage}.npz -o ${root_dir}/features/trojan/tsam_bs_filter_strip_${coverage}.npz -f tsam
# done

# Obtain MTSAF datasets
# nohup python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/normal/raw_bs_filter_strip.npz -o ${root_dir}/features/normal/mtsaf_bs_filter_strip.npz -f mtsaf &
# for coverage in "${coverages[@]}"; do
#     nohup python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/vmess/raw_bs_filter_strip_${coverage}.npz -o ${root_dir}/features/vmess/tsam_bs_filter_strip_${coverage}.npz -f tsam &
#     nohup python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/shadowsocks/raw_bs_filter_strip_${coverage}.npz -o ${root_dir}/features/shadowsocks/tsam_bs_filter_strip_${coverage}.npz -f tsam &
#     python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/trojan/raw_bs_filter_strip_${coverage}.npz -o ${root_dir}/features/trojan/tsam_bs_filter_strip_${coverage}.npz -f tsam
# done