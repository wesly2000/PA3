# Feature: DyWin
- **Branch: feature/dywin**
- **Date**: 2026-07-01
- **Author**: Linxiao Yu
- **Status**: WIP

## Motivation
We need to compare data enhancement methods as part of the main evaluation. This method DyWin is part of the paper titled *RoFiRe: Robust Website Fingerprinting on Real-World Tor Traffic via Improved Augmentation and Normalization* (WWW'26, Haeseung Jeon et. al.)

## Design && Implmentation
We respect the original implementation as much as possible. The original paper seems not to consider packet size much, which is necessary for a complete assessment of our repo, so we duplicate/remove the sizes within the window cell in the original paper as an extension.

## Usage
In the root dir of this repo, run `scripts/dywin/create_dataset.sh` to create the datasets. Then, run `scripts/dywin/all_models.sh` for a complete evaluation on all models.

## TODOs
+ [x] Implement DyWinAugmentor as a subclass of TrafficAugmentor;
+ [x] Test Traffic Augmentor.
+ [x] Corresponding dataset creating and training scripts;
+ [x] Documentation