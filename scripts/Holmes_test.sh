#!/bin/bash

checkpoints=${1:-normal}
dataset=${2:-CW}
device=${3:-"cuda:0"}
start=${4:-100}
batch_size=${4:-512}
attr_method=DeepLiftShap 

end=100
step=10

for ((percent=start; percent<=end; percent+=step));
do
    python -u exp/test_specific.py \
    --dataset ${dataset} \
    --checkpoints ${checkpoints} \
    --model Holmes \
    --device ${device} \
    --test_file taf_test_p${percent} \
    --feature TAF \
    --seq_len 2000 \
    --batch_size 256 \
    --eval_method Holmes \
    --eval_metrics Accuracy Precision Recall F1-score \
    --load_name max_f1 \
    --result_file ${checkpoints}_Holmes_p${percent}
done