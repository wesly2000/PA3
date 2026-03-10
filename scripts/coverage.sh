#!/bin/bash
# set -x
root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"

coverages=(5 6 7 8 9)

feature=dt
seq_len=10000

# python exp/dataset_process/gen_transformed.py --input_file ${root_dir}/features/normal/raw_bs_filter_strip.npz -o ${root_dir}/features/normal/${feature}_bs_filter_strip.npz -f ${feature} --seq_len=${seq_len}

for coverage in "${coverages[@]}"; do
    python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_bs_filter_strip_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/${feature}_bs_filter_strip_${coverage}.npz -f ${feature} --seq_len=${seq_len}
    python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/raw_bs_filter_strip_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/${feature}_bs_filter_strip_${coverage}.npz -f ${feature} --seq_len=${seq_len}
    python exp/dataset_process/gen_transformed.py --input_file /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/raw_bs_filter_strip_${coverage}.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/${feature}_bs_filter_strip_${coverage}.npz -f ${feature} --seq_len=${seq_len}
done

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