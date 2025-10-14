checkpoints=${1:-normal}
dataset=${2:-CW}
device=${3:-"cuda:1"}

seq_len=5000
feature=size_bin

python -u exp/test_specific.py \
  --dataset ${dataset} \
  --checkpoints ${checkpoints} \
  --model DF \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1 \
  --result_file ${checkpoints} 