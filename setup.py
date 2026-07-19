from setuptools import find_packages, setup
import sys

if sys.version_info < (3, 8):
    raise RuntimeError("Python version 3.8 or higher is required")

setup(
    name='pa3',
    version='0.2',
    description='pa3, an extended fork of WFlib. The original library is at https://github.com/Xinhao-Deng/Website-Fingerprinting-Library, by Xinhao Deng (dengxh23@mails.tsinghua.edu.cn) and Yixiang Zhang (zhangyix24@mails.tsinghua.edu.cn).',
    author='Linxiao Yu',
    packages=find_packages(include=["pa3", "pa3.*"]),
    install_requires=[
        "tqdm",
        "numpy",
        "pandas",
        "scikit-learn",
        "einops",
        "timm",
        "torch",
        "pytorch-metric-learning",
        "captum",
        "scapy",
        "selenium",
        "pyshark"
    ],
)