checkpoints=${1:-normal}
dataset=${2:-CW}
feature=${3:-"tam"}
device=${4:-"cuda:1"}

seq_len=1800

python -u exp/test_specific.py \
  --dataset ${dataset} \
  --checkpoints ${checkpoints} \
  --model RF \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --batch_size 256 \
  --eval_metrics F1-score \
  --load_name max_f1 \
  --result_file ${checkpoints} 