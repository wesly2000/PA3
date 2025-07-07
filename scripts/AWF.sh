dataset=${1:-CW}
device=${2:-"cuda:0"}
batch_size=${3:-128}

python -u exp/train.py \
  --dataset ${dataset} \
  --model AWF \
  --device ${device} \
  --feature DIR \
  --seq_len 3000 \
  --train_epochs 30 \
  --batch_size ${batch_size} \
  --learning_rate 8e-4 \
  --optimizer RMSprop \
  --eval_metrics Accuracy Precision Recall F1-score \
  --save_metric F1-score \
  --save_name max_f1

python -u exp/test.py \
  --dataset ${dataset} \
  --model AWF \
  --device ${device} \
  --feature DIR \
  --seq_len 3000 \
  --batch_size 256 \
  --eval_metrics Accuracy Precision Recall F1-score \
  --load_name max_f1