from WFlib.tools.domain_generalize import *
from WFlib.models.DF import *
from WFlib.tools import data_processor
import os
import argparse
from typing import List


def main(datasets: List[str], feature: str, model: str, device: str, num_tabs: int, seq_len: int, batch_size: int, num_workers: int):
    meta_train_X, meta_train_y, meta_valid_X, meta_valid_y = [], [], [], []
    train_X, train_y, val_X, val_y = None, None, None, None
    for dataset in datasets:
        in_path = os.path.join("./datasets", dataset)
        tmp_X, tmp_y = data_processor.load_data(os.path.join(in_path, f"train.npz"), feature, seq_len, num_tabs)
        meta_train_X.append(tmp_X)
        meta_train_y.append(tmp_y)
        if train_X is None:
            train_X = tmp_X
            train_y = tmp_y
        else:
            train_X = torch.cat((train_X, tmp_X), dim=0)
            train_y = torch.cat((train_y, tmp_y), dim=0)

        tmp_X, tmp_y = data_processor.load_data(os.path.join(in_path, f"valid.npz"), feature, seq_len, num_tabs)
        meta_valid_X.append(tmp_X)
        meta_valid_y.append(tmp_y)
        if val_X is None:
            val_X = tmp_X
            val_y = tmp_y
        else:
            val_X = torch.cat((val_X, tmp_X), dim=0)
            val_y = torch.cat((val_y, tmp_y), dim=0)

    train_iter = data_processor.load_iter(train_X, train_y, batch_size, True, num_workers)
    val_iter = data_processor.load_iter(val_X, val_y, batch_size, False, num_workers)

    meta_train_iter = [data_processor.load_iter(meta_train_X[i], meta_train_y[i], batch_size, True, num_workers) for i in range(len(datasets))]
    meta_val_iter = [data_processor.load_iter(meta_valid_X[i], meta_valid_y[i], batch_size, False, num_workers) for i in range(len(datasets))]

    FEATURE_MODEL_INPUT = 5000
    FEATURE_MODEL_OUTPUT = 80

    feature_model = FeatureModel(hidden_dim=FEATURE_MODEL_INPUT, num_classes=FEATURE_MODEL_OUTPUT).to(device)
    HIDDEN_DIM = feature_model.output_dim()

    task_model_1 = TaskModel(feature_model=feature_model, hidden_dim=HIDDEN_DIM, num_classes=FEATURE_MODEL_OUTPUT).to(device)
    task_model_2 = TaskModel(feature_model=feature_model, hidden_dim=HIDDEN_DIM, num_classes=FEATURE_MODEL_OUTPUT).to(device)

    task_models = [task_model_1, task_model_2]

    regularizer = Regularizer(hidden_dim=task_model_1.trainable_param().shape[0], num_classes=FEATURE_MODEL_OUTPUT).to(device)
    feature_model_final = FeatureModel(hidden_dim=FEATURE_MODEL_INPUT, num_classes=FEATURE_MODEL_OUTPUT).to(device)
    model_final = TaskModel(feature_model_final, hidden_dim=HIDDEN_DIM, num_classes=FEATURE_MODEL_OUTPUT).to(device)

    meta_reg = MetaReg(task_models, regularizer, model_final, device=device)
    meta_reg.train(meta_train_iter, meta_val_iter, train_iter, val_iter)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WFlib")
    parser.add_argument("--datasets", nargs='+', required=True, type=str, help="Dataset name")
    parser.add_argument("--use_stratify", type=str, default="True", help="Whether to use stratify")
    # parser.add_argument("-f", "--feature", type=str, default="X", help="The name of features to use")
    parser.add_argument("--model", type=str, default="DF", help="Model name")
    parser.add_argument("--device", type=str, default="cpu", help="Device, options=[cpu, cuda, cuda:x]")
    parser.add_argument("--num_tabs", type=int, default=1, 
                        help="Maximum number of tabs opened by users while browsing")
    parser.add_argument("--seq_len", type=int, default=5000, help="Input sequence length")
    parser.add_argument("--batch_size", type=int, default=256, help="Batch size of train input data")
    parser.add_argument("--num_workers", type=int, default=10, help="Data loader num workers")
    parser.add_argument("--feature", type=str, default="DIR", 
                    help="Feature type, options=[DIR, DT, DT2, TAM, TAF]")

    args = parser.parse_args()
    # Load training and validation data
    main(args.datasets, args.feature, args.model, args.device, args.num_tabs, args.seq_len, args.batch_size, args.num_workers)