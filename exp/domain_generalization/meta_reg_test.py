from pa3.tools.domain_generalize import *
from pa3.models.DF import *
from pa3.tools import data_processor
import os
import argparse
from typing import List


def test(final_model: nn.Module, test_data: DataLoader, device: str) -> None:
    eval_metrics = ["Accuracy", "Precision", "Recall", "F1-score"]
    save_metric = "F1-score"

    with torch.no_grad():
        final_model.eval()
        y_pred = []
        y_true = []

        for test_batch in test_data:
            X, y = test_batch[0].to(device), test_batch[1].to(device)
            outputs = final_model(X)
            pred = torch.argsort(outputs, dim=1, descending=True)[:,0]
            
            y_pred.append(pred.cpu().numpy())
            y_true.append(y.cpu().numpy())

        y_pred = np.concatenate(y_pred)
        y_true = np.concatenate(y_true)

        test_result = measurement(y_true, y_pred, eval_metrics, 1)
        print(f"Test {save_metric}: {test_result[save_metric]}")


def main(datasets: List[str], feature: str, model: str, device: str, num_tabs: int, seq_len: int, batch_size: int, num_workers: int):
    test_X, test_y = None, None
    for dataset in datasets:
        in_path = os.path.join("./datasets", dataset)
        # Load test iter
        tmp_X, tmp_y = data_processor.load_data(os.path.join(in_path, f"test.npz"), feature, seq_len, num_tabs)
        if test_X is None:
            test_X = tmp_X
            test_y = tmp_y
        else:
            test_X = torch.cat((test_X, tmp_X), dim=0)
            test_y = torch.cat((test_y, tmp_y), dim=0)

    test_iter = data_processor.load_iter(test_X, test_y, batch_size, False, num_workers)
    
    in_file = f"./checkpoints/best_model_F1-score.pth"
    FEATURE_MODEL_INPUT = 5000
    FEATURE_MODEL_OUTPUT = 80
    feature_model = FeatureModel(hidden_dim=FEATURE_MODEL_INPUT, num_classes=FEATURE_MODEL_OUTPUT).to(device)
    HIDDEN_DIM = feature_model.output_dim()

    feature_model_final = TaskModel(feature_model=feature_model, hidden_dim=HIDDEN_DIM, num_classes=FEATURE_MODEL_OUTPUT).to(device)
    feature_model_final.load_state_dict(torch.load(in_file))
    feature_model_final.to(device)

    test(feature_model_final, test_iter, device)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="pa3")
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