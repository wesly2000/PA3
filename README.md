<p align="center">
<img src=".\figures\PA3.png" height = "180" alt="" align=center />
<br><br>
</p>


PA3 is an open-source library for website fingerprinting attacks on *proxied traffic*, intended for research purposes only.

Website fingerprinting is a type of network attack in which an adversary attempts to deduce which website a user is visiting based on encrypted traffic patterns, even without directly seeing the content of the traffic. However, due to the diversity of proxy protocols, the well-trained WF models may encounter traces in the testing dataset from unseen protocols, incurring a severe performance degradation.

PA3 consists of 2 parts: 

1. Analyze how the proxy protocol affects the normal HTTPS traffic;
2. Mitigate the impacts of proxy protocol to improve WF model generalization on unseen protocols.

The main challenge here is that proxied traffic is further encrypted and obfuscated. Therefore, the philosophy behind PA3 is **induction for deduction**, i.e., we decrypt and parse a small amount of proxied traffic to learn how the corresponding protocol affects traffic feature. The learned knowledge are concluded into protocol-specific knowledge (induction). Then, we apply these knowledge on encrypted proxied traffic based on some statistics to mitigate the impacts (deduction).

To facilitate this, PA3 actually consists of many sub-repoes, including the proxy key logger, Wireshark dissectors for proxy protocols, WF model training module, proxied network traffic collector, etc. They are implemented in different languages, including C, Go and Python, thus could not be included into a singe repo.

For paper results reproduction purpose, we only need the Python repo, which should be self-contained to reproduce **all results in this paper**. We have already release the processed data in .npz format to train the WF models. Recognizing the importance of the original network traffic (.pcap format), we also release them along with the keys such that you can parse them to obtain new observations.

*Other repoes are not provided now since we need to anonymize the repo information in paper submission stage. Providing a lot of links in the paper might make it cumbersome. Later they would be released together.*

## Installation
Clone this repo, and in the repo root, execute (conda or other venv manager is highly recommended):
```
pip install --user .
```
a Python >= 3.8 is required. We've tested version 3.9.18 on `Debian GNU/Linux 10` and version 3.10.9 on `Windows 11`.

After installation, in the repo root, run
```
pytest exp/tests
```
all tests should pass. It is normal that some tests are skipped since Wireshark plugins are not installed, so parsing and decrypting proxied traffic from `.pcap` is not possible. So, we don't need the corresponding tests. The parsing results are prepared in `VisualSeg`. After *de-anonymization*, these plugins would be released. Parsing from the source `.pcap` files would be valid at that time.

If the `bash` scripts could not be executed normally, please use
```
chmod +x [script name].sh
```
to allow execution.

## Dataset Preparation
We upload the datasets to `storage.to` for anonymity, which includes 2 links: [VisualSeg](https://storage.to/c/GA8L6yRhs), which is used to reproduce the *structual fingerprinting* results, and [Reproduce](https://storage.to/c/524xauyCl), which is used to reproduce WF model performance with several drift mitigating methods, plus the ablation study.

Please unzip all `.tar.gz` files under `Reproduce` and `VisualSeg`. Make `results` and `workspace` directories under `Reproduce`. The whole dataset directory structure should look like:

```
[PA3_REPO_ROOT]
       |--------Reproduce
       |            |------ablation <-- dataset for ablation study
       |            |------features <-- dataset for comparison evaluation
       |            |------results  <-- used to store evaluation results
       |            |------workspace<-- used to temporary evaluation results
       |
       |--------VisualSeg <-- data for traffic analysis
       
```

Before reproduction, please create `.env` and configure `PA3_REPO_ROOT`. The whole repo relies this variable to locate the data. `.env.example` gives an example configuration.

## Payload-Aware Analysis
Most of the *structual fingerprinting* results could be reproduced using `exp/data_analysis/reproduction.ipynb`. Simply run the cells one by one.

## Drift Mitigation for WF models
As described in the paper, we evaluate 6 WF models: `DF, BAPM, NetCLR, TF, TikTok` and `RF`. To mitigate the proxy-induced drift, we have 6 methods: `baseline, dywin, netclr (NetAugment), rosetta, netrand (NetRandAugment)` and `pa3`.

If you want to reproduce the results for `pa3`, simply run:
```
./scripts/pa3/all_models.sh
```
After training and testing, there would be multiple results under `Reproduce/workspace`, like:

```
[PA3_REPO_ROOT]
       |--------Reproduce
       |            |------ablation 
       |            |------features 
       |            |------results  
       |            |------workspace
       |                       |------shadowsocks_size_bin_DF.json
       |                       |------vmess_dt_TikTok.json
       |                       |------......
       |--------VisualSeg
```
A `[training protocol][feature][model name].json` result file summarise the testing results on the testing protocol using the WF model trained on the training protocol.

Then create the mitigation method (here we use `pa3`) under `Reproduce/results` and move all the json files under that directory to store the results, like the following
```
[PA3_REPO_ROOT]
       |--------Reproduce
       |            |------ablation 
       |            |------features 
       |            |------results
       |            |         |------pa3
       |            |         |       |------shadowsocks_size_bin_DF.json
       |            |         |       |------vmess_dt_TikTok.json
       |            |         |       |------......  
       |            |         |------rosseta
       |            |         |------......
       |            |------workspace
       |                       
       |                       
       |                       
       |--------VisualSeg
```
Then, use `exp/data_analysis/wf_results.ipynb` for better results parsing (because we will run several times per model). Change `method` to the method run the `all_model.sh` and it should print the results in LaTeX &-separate strings, like:
```
Training protocol: vmess
Shadowsocks: 0.774 ($\pm 0.008$) & 0.653 ($\pm 0.008$) ...
Trojan: 0.633 ($\pm 0.011$) & 0.582 ($\pm 0.005$) ...
```

For ablation study, simply run 
```
./script/ablation/ablation.sh
```
then put the resulting json files under `Reproduce/results/ablation`.