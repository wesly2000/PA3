# Positional args: $1 dataset (default CW), $2 feature, $3 device,
# $4 optional pretrain source dataset (omit, empty, or None = skip pretrain; else e.g. NCDrift_sup),
# $5 batch_size (default 256). Previously $4 defaulted to NCDrift_sup; pass it explicitly to keep that behavior.

dataset=${1:-CW}
feature=${2:-"size_bin"}
device=${3:-"cuda:0"}
pretrain_dataset=${4:-}
batch_size=${5:-256}

seq_len=5000

use_pretrain=1
if [[ -z "$pretrain_dataset" || "${pretrain_dataset,,}" == "none" ]]; then
  use_pretrain=0
fi

if [[ "$use_pretrain" -eq 1 ]]; then
  python -u exp/pretrain.py \
    --dataset ${pretrain_dataset} \
    --feature ${feature} \
    --model NetCLR \
    --device ${device} \
    --train_epochs 30 \
    --batch_size ${batch_size} \
    --learning_rate 3e-4 \
    --optimizer Adam \
    --save_name pretrain
fi

load_args=()
if [[ "$use_pretrain" -eq 1 ]]; then
  load_args=(--load_file "${pretrain_dataset}/NetCLR/pretrain.pth")
fi

python -u exp/train.py \
  --dataset ${dataset} \
  --model NetCLR \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --train_epochs 30 \
  --batch_size ${batch_size} \
  --learning_rate 3e-4 \
  --optimizer Adam \
  --eval_metrics Accuracy Precision Recall F1-score \
  --save_metric Accuracy \
  "${load_args[@]}" \
  --save_name max_f1

python -u exp/test.py \
  --dataset ${dataset} \
  --model NetCLR \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1
