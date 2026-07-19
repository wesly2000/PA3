from torch import nn, optim
from torch.utils.data import DataLoader
from typing import List
import numpy as np
import torch
import random
import copy
from math import ceil
from pa3.utils.statistics import sample
from pa3.tools.evaluator import measurement
from pa3.models.DF import ConvBlock


class MetaReg():
    """
    The MetaReg DG training strategy by NIPS 18 MetaReg: Towards Domain Generalization using Meta-Regularization
    The main idea is as follows:
    The training process is divided into two stages: meta-training and final-training.

    The real loss function is L_reg = L + R, where R is the regularizer which confines domain-specific features,
    meta-training is to learn the regularizer R.
    ```
        |-\\     /----->T_1
        |  \\   /
    --->| F |---------->T_2
        |  /   \\
        |-/     \\----->T_3
    ```

    Final-training is to train the final model (ToF)(x) with the regularizer R.

    --->F---->T
    """


    def __init__(self, 
                 task_models: List[nn.Module], 
                 regularizer: nn.Module,
                 final_model: nn.Module,
                 lr: float = 0.001,
                 device: str='cpu',
                 meta_train_steps: int = 20,
                 epochs_metatrain: int = 20,
                 epochs: int = 50,
                 ) -> None:
        self.task_models = task_models
        self.regularizer = regularizer
        self.final_model = final_model
        self.device = device
        self.lr = lr
        self.meta_train_steps = meta_train_steps
        self.epochs_metatrain = epochs_metatrain
        self.epochs = epochs
        self.loss_function = nn.CrossEntropyLoss()
        self.loss_name = "CrossEntropyLoss"
        self.task_optimizers = [optim.SGD(task_model.parameters(), lr=lr, momentum=.9) for task_model in self.task_models]
        self.final_optimizer = optim.SGD(self.final_model.parameters(), lr=lr, momentum=.9)

    def _meta_train_epoch(self, train_data: List[DataLoader]) -> None:
        def meta_train_step_1(train_batch: List[DataLoader]):
            # Train F and T_i with as the normal training process
            for i in range(len(train_batch)):
                X, y = train_batch[i]
                X = X.to(self.device)
                y = y.to(self.device)

                task_model_loss = self.loss_function(self.task_models[i](X), y)
                self.task_optimizers[i].zero_grad()
                task_model_loss.backward()
                self.task_optimizers[i].step()

        def meta_train_step_2(train_batch: List[DataLoader], models: List[nn.Module], random_domains: np.ndarray):
            # Train F and T_i with as the normal training process
            X, y = train_batch[random_domains[0]]
            X = X.to(self.device)
            y = y.to(self.device)

            # Use the model parameter as the initial parameter to remove the gradient trace of previous steps
            optimizer = optim.SGD(self.task_models[random_domains[0]].parameters(), lr=self.lr, momentum=.9)
            meta_train_loss = self.loss_function(self.task_models[random_domains[0]](X), y) + self.regularizer(torch.abs(self.task_models[random_domains[0]].trainable_param()))
            optimizer.zero_grad()
            meta_train_loss.backward()
            optimizer.step()

        def meta_train_step_3(train_batch: List[DataLoader], models: List[nn.Module], random_domains: np.ndarray, optimizer_reg: optim.Optimizer):
            # get gradients and apply SGD
            meta_test_model = models[random_domains[1]]
            inputs = train_batch[random_domains[1]]
            meta_test_loss = self.loss_function(meta_test_model(inputs[0].to(self.device)), inputs[1].to(self.device))
            # zero the parameter gradients
            optimizer_reg.zero_grad()
            # perform gradient descent
            meta_test_loss.backward()
            optimizer_reg.step()

        for i in range(len(self.task_models)):
            self.task_models[i].train()

        # TRAIN STEP 1, regular training (line 2-7 in MetaReg algo)
        for i, train_batch in enumerate(zip(*train_data)):
            meta_train_step_1(train_batch)
                        
        # sample two random domains
        random_domains = random.sample(range(len(self.task_models)), 2)
        models = [copy.deepcopy(self.task_models[i]) for i in range(len(self.task_models))]
        # meta_train_sample = sample(zip(*train_data), self.meta_train_steps)

        # TRAIN STEP 2, meta learning of regularizer (line 10-13 in MetaReg algo)
        for meta_train_sample_step in zip(*train_data):
            meta_train_step_2(meta_train_sample_step, models, random_domains)

        optimizer_reg = optim.SGD(self.regularizer.parameters(), lr=self.lr, momentum=0.9)
        # TRAIN STEP 3, update regularizer NN (line 16 in MetaReg algo)
        for meta_train_sample_step in zip(*train_data):
            meta_train_step_3(meta_train_sample_step, models, random_domains, optimizer_reg)


    def _train_epoch(self, train_data: DataLoader, epoch: int) -> None:
        self.final_model.train()
        sum_loss = 0
        sum_count = 0

        def train_step(train_batch: DataLoader):
            self.final_model.train()
            X, y = train_batch[0].to(self.device), train_batch[1].to(self.device)
            self.final_optimizer.zero_grad()
            # Regularization loss is negative
            loss_final = self.loss_function(self.final_model(X), y) + self.regularizer(torch.abs(self.final_model.trainable_param()))
            loss_final.backward()
            self.final_optimizer.step()
            loss = loss_final.data.cpu().numpy() * X.shape[0]
            count = X.shape[0]

            return loss.item(), count  # Why loss is an array instead of a scalar?

        for train_batch in train_data:
            loss, count = train_step(train_batch)
            sum_loss += loss
            sum_count += count

        train_loss = round(sum_loss / sum_count, 3)
        print(f"epoch {epoch}: train_loss = {train_loss}")

    def _validate_epoch(self, model: nn.Module, val_data: DataLoader, eval_metrics: List[str], num_tabs: int=1) -> None:
        with torch.no_grad():
            model.eval()
            valid_pred = []
            valid_true = []

            for _, cur_data in enumerate(val_data):
                cur_X, cur_y = cur_data[0].to(self.device), cur_data[1].to(self.device)
                outs = model(cur_X)
                
                if self.loss_name in ["BCEWithLogitsLoss", "MultiLabelSoftMarginLoss"]:
                    cur_pred = torch.sigmoid(outs)
                elif self.loss_name == "CrossEntropyLoss":
                    cur_pred = torch.argsort(outs, dim=1, descending=True)[:,0]
                elif self.loss_name == "MultiCrossEntropyLoss":
                    raise NotImplementedError("MultiCrossEntropyLoss is not implemented for final model.")
                    # cur_indices = torch.argmax(outs, dim=-1).cpu()
                    # cur_pred = torch.zeros((cur_indices.shape[0], self.num_classes))
                    # for cur_tab in range(cur_indices.shape[1]):
                    #     row_indices = torch.arange(cur_pred.shape[0])
                    #     cur_pred[row_indices,cur_indices[:,cur_tab]] += 1
                else:
                    raise ValueError(f"Loss function {self.loss_name} is not matched.")

                valid_pred.append(cur_pred.cpu().numpy())
                valid_true.append(cur_y.cpu().numpy())
            
            valid_pred = np.concatenate(valid_pred)
            valid_true = np.concatenate(valid_true)

        valid_result = measurement(valid_true, valid_pred, eval_metrics, num_tabs=num_tabs)
        return valid_result
                

    def train(self, meta_train_data: List[DataLoader], meta_val_data: List[DataLoader], train_data: DataLoader, val_data: DataLoader) -> None:
        eval_metrics = ["Accuracy", "Precision", "Recall", "F1-score"]
        save_metric = "F1-score"

        for epoch in range(self.epochs_metatrain):  
            self._meta_train_epoch(meta_train_data)
            for i in range(len(self.task_models)):
                valid_result = self._validate_epoch(self.task_models[i], meta_val_data[i], eval_metrics)
                print(f"Task model {i}: {save_metric}={valid_result[save_metric]}")

        metric_best_value = 0
        best_epoch = 0
        out_file = f"./checkpoints/best_model_{save_metric}.pth"

        for epoch in range(self.epochs):
            self._train_epoch(train_data, epoch)
            # Validation phrase
            valid_result = self._validate_epoch(self.final_model, val_data, eval_metrics)
            if valid_result[save_metric] > metric_best_value:
                metric_best_value = valid_result[save_metric]
                best_epoch = epoch
                torch.save(self.final_model.state_dict(), out_file)
            print(f"best epoch {best_epoch}: {save_metric}={metric_best_value}")


class TaskModel(nn.Module):
    def __init__(self, feature_model: nn.Module, hidden_dim: int, num_classes: int):
        super(TaskModel, self).__init__()
        self.num_classes = num_classes
        self.feature_model = feature_model

        self.classifier = nn.Sequential(
            nn.Flatten(),  # Flatten the tensor to a vector
            nn.Linear(hidden_dim, 512, bias=False),  # Fully connected layer
            nn.BatchNorm1d(512),  # Batch normalization layer
            nn.ReLU(inplace=True),  # ReLU activation function
            nn.Dropout(p=0.7),  # Dropout layer for regularization
            nn.Linear(512, 512, bias=False),  # Fully connected layer
            nn.BatchNorm1d(512),  # Batch normalization layer
            nn.ReLU(inplace=True),  # ReLU activation function
            nn.Dropout(p=0.5),  # Dropout layer for regularization
            nn.Linear(512, num_classes)  # Output layer
        )

    def trainable_param(self):
        return torch.cat([p.flatten() for p in self.classifier.parameters() if p.requires_grad])

    def logits(self, input):
        x = self.feature_model(input)
        x = self.classifier(x)
        return x

    def forward(self, input):
        x = self.logits(input)
        return x
    

class FeatureModel(nn.Module):
    def __init__(self, hidden_dim, num_classes):
        super(FeatureModel, self).__init__()

        def length_after_extraction(input_length: int):
            output_length = input_length
            for _ in filter_num:
                output_length = (output_length - pool_size) // pool_stride_size + 1
            return output_length
        
        # Configuration parameters for the convolutional blocks
        filter_num = [32, 64, 128, 256]  # Number of filters for each block
        kernel_size = 8  # Kernel size for convolutional layers
        conv_stride_size = 1  # Stride size for convolutional layers
        pool_stride_size = 4  # Stride size for max pooling layers
        pool_size = 8  # Kernel size for max pooling layers
        self._length_after_extraction = length_after_extraction(hidden_dim)
        self._output_dim = self._length_after_extraction * filter_num[-1]
        
        # Define the feature extraction part of the network using a sequential container with ConvBlock instances
        self.feature_extraction = nn.Sequential(
            ConvBlock(1, filter_num[0], kernel_size, conv_stride_size, pool_size, pool_stride_size, 0.1, nn.ELU),  # Block 1
            ConvBlock(filter_num[0], filter_num[1], kernel_size, conv_stride_size, pool_size, pool_stride_size, 0.1, nn.ReLU),  # Block 2
            ConvBlock(filter_num[1], filter_num[2], kernel_size, conv_stride_size, pool_size, pool_stride_size, 0.1, nn.ReLU),  # Block 3
            ConvBlock(filter_num[2], filter_num[3], kernel_size, conv_stride_size, pool_size, pool_stride_size, 0.1, nn.ReLU)  # Block 4
        )

    def output_dim(self):
        return self._output_dim

    def forward(self, x):
        # Pass the input through the feature extraction part
        x = self.feature_extraction(x)
        return x

    
class Regularizer(nn.Module):
   def __init__(self, hidden_dim, num_classes):
      super(Regularizer, self).__init__()
      self.num_classes = num_classes
      self.linear1 = nn.Linear(hidden_dim, 1, bias=False)

   def logits(self, input):
      x = self.linear1(input)
      return x

   def forward(self, input):
    #   input = input.cuda()
      x = self.logits(input)
      return x