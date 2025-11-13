dataset=${1:-CW}
feature=${2:-"size_bin"}
device=${3:-"cuda:0"}
pretrain_dataset=${4:-NCDrift_sup}
batch_size=${5:-256}

seq_len=5000

python -u exp/pretrain.py \
  --dataset ${pretrain_dataset} \
  --feature ${feature} \
  --model NetCLR \
  --device ${device} \
  --train_epochs 100 \
  --batch_size ${batch_size} \
  --learning_rate 3e-4 \
  --optimizer Adam \
  --save_name pretrain

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
  --load_file ${pretrain_dataset}/NetCLR/pretrain.pth \
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
