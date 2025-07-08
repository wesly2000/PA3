dataset=${1:-CW}
device=${2:-"cuda:0"}
batch_size=${3:-200}

feature=tsam
seq_len=1800

python -u exp/train.py \
  --dataset ${dataset} \
  --model RF \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --train_epochs 30 \
  --batch_size ${batch_size} \
  --learning_rate 5e-4 \
  --optimizer Adam \
  --eval_metrics Accuracy Precision Recall F1-score \
  --save_metric F1-score \
  --save_name max_f1

python -u exp/test.py \
  --dataset ${dataset} \
  --model RF \
  --device ${device} \
  --feature ${feature} \
  --seq_len ${seq_len} \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1