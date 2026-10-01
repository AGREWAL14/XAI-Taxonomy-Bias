# Decisions

Append-only. Corrections are appended as new entries, never edited in.

## 2026-10-01 — Repository created, scope separated from AG_PRAXIS

This repository examines one reported (not hypothesis-tested) result from AG_PRAXIS
H3 — the 9/18 semantic agreement figure — and asks whether the SHAP-to-CAPEC-to-STRIDE
mapping rule is structurally biased. It makes no claim on H1, H2, H3's pass/fail
status, or any other AG_PRAXIS finding. `config/` and `data/raw/` are read-only copies;
see `data/PROVENANCE.md`.

## 2026-10-01 — Structural entry-density finding established without model output

Computed directly from `config/shap_capec_map.yaml` and `config/capec_stride.yaml`:
Information Disclosure holds 17 of 29 feature-to-CAPEC entries while covering 4 of 18
ground-truth classes; Denial of Service holds 11 of 29 while covering 12 of 18;
Tampering and Spoofing each hold exactly 1. This does not depend on any attribution
value and is reproducible by anyone reading the config files. Script:
`analysis/audit_mapping_bias.py`, output: `results/entry_density.csv`.

## 2026-10-01 — All 9 recorded disagreements cross-checked against the structural finding

Using only the top-5 features AG_PRAXIS's `threat_mapping.json` already records per
class (not the full top-10, not raw SHAP magnitudes), all 9 of the sequence model's
18 classes that disagree with ground truth resolve to one of three mechanisms: (1)
multi-candidate dilution toward Information Disclosure via features with 2-3 CAPEC
entries, (2) volume features (Number/Tot sum/Weight/Tot size) being Denial-of-Service-
only in the config, (3) Tampering and Spoofing each being reachable through exactly one
feature in the entire 40-feature map. Output: `results/disagreement_mechanisms.csv`.

**Open item:** this confirms the mechanism is *consistent with* the structural bias,
not that attribution mass was *provably* the deciding factor in each case (that would
need AG_PRAXIS's `attributions_seed_*.npz` files — ranks 6-10 and raw magnitudes —
which are not in this repository). The structural claim does not depend on this; a
confirmatory check would strengthen but is not required for the paper's main argument.
