#!/bin/bash

python exp/dataset_process/dataset_merge.py -i /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/size_pa3_trojan.npz /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/size_pa3_shadowsocks.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/size_pa3.npz

python exp/dataset_process/dataset_merge.py -i /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/size_pa3_trojan.npz /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/size_pa3_vmess.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/size_pa3.npz

python exp/dataset_process/dataset_merge.py -i /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/size_pa3_vmess.npz /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/size_pa3_shadowsocks.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/size_pa3.npz

python exp/dataset_process/dataset_merge.py -i /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/tsam_pa3_trojan.npz /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/tsam_pa3_shadowsocks.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/vmess/tsam_pa3.npz

python exp/dataset_process/dataset_merge.py -i /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/tsam_pa3_trojan.npz /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/tsam_pa3_vmess.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/shadowsocks/tsam_pa3.npz

python exp/dataset_process/dataset_merge.py -i /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/tsam_pa3_vmess.npz /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/tsam_pa3_shadowsocks.npz -o /data/exp/lxyu/Dataset/WF/Reproduce/features/trojan/tsam_pa3.npz