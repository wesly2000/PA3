#!/bin/bash
# set -x

# vmess
#   |--raw.npz
#   |--raw_bs_filter_5.npz 
#   |--raw_bs_filter_strip_5.npz 
#   |--raw_bs_filter_strip_5_aug_slope_shadowsocks.npz 
#   |--raw_bs_filter_strip_5_aug_slope_trojan.npz
#   |--raw_host_filter_strip_aug_slope_shadowsocks.npz
#   |--raw_host_filter_strip_aug_slope_trojan.npz
# shadowsocks 
#   |--raw.npz
#   |--raw_bs_filter_5.npz 
#   |--raw_bs_filter_strip_5.npz 
#   |--raw_bs_filter_strip_5_aug_slope_vmess.npz 
#   |--raw_bs_filter_strip_5_aug_slope_trojan.npz 
#   |--raw_host_filter_strip
# trojan 
#   |--raw.npz
#   |--raw_bs_filter_4.npz 
#   |--raw_bs_filter_strip_4.npz 
#   |--raw_bs_filter_strip_4_aug_slope_shadowsocks.npz 
#   |--raw_bs_filter_strip_4_aug_slope_vmess.npz 
#   |--raw_host_filter_strip

root_dir="/data/exp/lxyu/Dataset/WF/Reproduce"

seq_len=10000

vmess_coverage=4
shadowsocks_coverage=4
trojan_coverage=4

# NoProxy dataset creation
# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p normal -o ${root_dir}/features/normal/raw.npz --bs_filter --feature raw &

# VMess dataset creation
# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/features/vmess/raw.npz --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/features/vmess/raw_bs_filter_${vmess_coverage}.npz --bs_filter --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/features/vmess/raw_bs_filter_strip_${vmess_coverage}.npz --bs_filter --strip --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks.npz --bs_filter --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/shadowsocks_vmess_slope_ratio.npz --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_known_slope_shadowsocks.npz --bs_filter --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/shadowsocks_vmess_slope_ratio.npz --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_slope_trojan.npz --bs_filter --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/trojan_vmess_slope_ratio.npz --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_known_slope_trojan.npz --bs_filter --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/trojan_vmess_slope_ratio.npz --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_shadowsocks.npz -f exp/data_extract/filter.txt --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/shadowsocks_vmess_slope_ratio.npz --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_trojan.npz -f exp/data_extract/filter.txt --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/trojan_vmess_slope_ratio.npz --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks_gaussian.npz --bs_filter --strip --slope shadowsocks --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o ${root_dir}/features/vmess/raw_bs_filter_strip_${vmess_coverage}_aug_slope_trojan_gaussian.npz --bs_filter --strip --slope trojan --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_shadowsocks_gaussian.npz -f exp/data_extract/filter.txt --strip --slope shadowsocks --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip_aug_slope_trojan_gaussian.npz -f exp/data_extract/filter.txt --strip --slope trojan --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p vmess -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/raw_host_filter_strip.npz -f exp/data_extract/filter.txt --strip --feature raw &

# Shadowsocks dataset creation
# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o ${root_dir}/features/shadowsocks/raw.npz --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o ${root_dir}/features/shadowsocks/raw_bs_filter_${shadowsocks_coverage}.npz --bs_filter --coverage .${shadowsocks_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o ${root_dir}/features/shadowsocks/raw_bs_filter_strip_${shadowsocks_coverage}.npz --bs_filter --strip --coverage .${shadowsocks_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o ${root_dir}/features/shadowsocks/raw_bs_filter_strip_${shadowsocks_coverage}_aug_slope_vmess.npz --bs_filter --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/vmess_shadowsocks_slope_ratio.npz --coverage .${shadowsocks_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o ${root_dir}/features/shadowsocks/raw_bs_filter_strip_${shadowsocks_coverage}_aug_slope_trojan.npz --bs_filter --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/trojan_shadowsocks_slope_ratio.npz --coverage .${shadowsocks_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o ${root_dir}/features/shadowsocks/raw_host_filter_strip.npz -f exp/data_extract/filter.txt --strip --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o ${root_dir}/features/shadowsocks/raw_bs_filter_strip_${vmess_coverage}_aug_slope_vmess_gaussian.npz --bs_filter --strip --slope vmess --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p shadowsocks -o ${root_dir}/features/shadowsocks/raw_bs_filter_strip_${vmess_coverage}_aug_slope_trojan_gaussian.npz --bs_filter --strip --slope trojan --coverage .${vmess_coverage} --feature raw &

# Trojan dataset creation
# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o ${root_dir}/features/trojan/raw.npz --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o ${root_dir}/features/trojan/raw_bs_filter_${trojan_coverage}.npz --bs_filter --coverage .${trojan_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o ${root_dir}/features/trojan/raw_bs_filter_strip_${trojan_coverage}.npz --bs_filter --strip --coverage .${trojan_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o ${root_dir}/features/trojan/raw_bs_filter_strip_${trojan_coverage}_aug_slope_shadowsocks.npz --bs_filter --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/shadowsocks_trojan_slope_ratio.npz --coverage .${trojan_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o ${root_dir}/features/trojan/raw_bs_filter_strip_${trojan_coverage}_aug_slope_vmess.npz --bs_filter --strip --slope /data/exp/lxyu/Dataset/WF/VisualSeg/slope/vmess_trojan_slope_ratio.npz --coverage .${trojan_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o ${root_dir}/features/trojan/raw_host_filter_strip.npz -f exp/data_extract/filter.txt --strip --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o ${root_dir}/features/trojan/raw_bs_filter_strip_${vmess_coverage}_aug_slope_vmess_gaussian.npz --bs_filter --strip --slope vmess --coverage .${vmess_coverage} --feature raw &

# nohup python exp/data_extract/csv_batch_extract.py -d /data/exp/lxyu/Dataset/WF/VisualSeg/csv_db_extract -p trojan -o ${root_dir}/features/trojan/raw_bs_filter_strip_${vmess_coverage}_aug_slope_shadowsocks_gaussian.npz --bs_filter --strip --slope shadowsocks --coverage .${vmess_coverage} --feature raw &