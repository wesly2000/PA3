checkpoints=${1:-normal}
dataset=${2:-CW}
feature=${3:-"mtaf"}
device=${4:-"cuda:0"}

seq_len=8000

python -u exp/test_specific.py \
  --dataset ${dataset} \
  --checkpoints ${checkpoints} \
  --model ARES \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1 \
  --result_file ${checkpoints} 