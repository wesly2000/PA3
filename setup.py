from setuptools import find_packages, setup
import sys

if sys.version_info < (3, 8):
    raise RuntimeError("Python version 3.8 or higher is required")

setup(
    name='pa3',
    version='0.2',
    description='PA3: a framework for proxy-induced drift mitigation',
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
        "pyshark",
        "pytest",
        "nest_asyncio"
    ],
)