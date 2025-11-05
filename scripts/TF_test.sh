checkpoints=${1:-normal}
dataset=${2:-CW}
feature=${3:-"size"}
device=${4:-"cuda:0"}

seq_len=5000

python -u exp/test_specific.py \
  --dataset ${dataset} \
  --checkpoints ${checkpoints} \
  --model TF \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1 \
  --eval_method kNN \
  --result_file ${checkpoints}_TF