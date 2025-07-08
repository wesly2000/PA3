dataset=${1:-CW}
device=${2:-"cuda:0"}
checkpoints=${3:-normal}

feature=tsam
seq_len=1800

python -u exp/test_specific.py \
  --dataset ${dataset} \
  --checkpoints ${checkpoints} \
  --model RF \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1 \
  --result_file ${checkpoints} 