dataset=${1:-CW}
feature=${2:-"mtaf"}
device=${3:-"cuda:0"}
batch_size=${4:-200}

seq_len=8000

python -u exp/train.py \
  --dataset ${dataset} \
  --model ARES \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --train_epochs 30 \
  --batch_size ${batch_size} \
  --learning_rate 2e-3 \
  --optimizer AdamW \
  --lradj StepLR \
  --eval_metrics Accuracy Precision Recall F1-score \
  --save_metric F1-score \
  --save_name max_f1

python -u exp/test.py \
  --dataset ${dataset} \
  --model ARES \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1