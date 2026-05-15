# Feature: Coverage Analysis
- **Branch: feature/coverage-analysis**
- **Date**: 2026-05-13
- **Author**: Linxiao Yu
- **Status**: WIP

## Motivation
- Observing the DF performance on Trojan declines sharply when $\alpha>0.4$, while that on Shadowsocks is much stable, which is quite interesting. We want to validate if it is because that when $\alpha>0.4$, a lot of website flows are filtered out, causing severe performance degradation.
- **Research Goal**: To predict the performace degradation by observing the website flow filtration proportion.

## Design && Implmentation
Currently, the goals include mainly in 2 sides:

1. Visualize the proportion of BIH flows to all flows;
2. Visualize the relationship between $\alpha$ and the proportion of filtered website flows to all website flows.

## TODOs
+ [x] Website flow sizes KDE
+ [ ] BIH flow size range in KDE
+ [ ] Coverage website flow filtration relationship.