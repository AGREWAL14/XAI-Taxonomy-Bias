# Provenance

All files under `config/` and `data/raw/` originate from the AG_PRAXIS repository
(GWU D.Eng praxis, "Explainable Sequence-Based Intrusion Detection for Threat Modeling
in Internet of Medical Things Networks"). They are copied here read-only as inputs to
an independent analysis and are not modified by anything in this repository.

| File | Origin | Committed / generated |
|---|---|---|
| `config/stride_ground_truth.yaml` | AG_PRAXIS, committed before any model trained | 2026-08-11 |
| `config/capec_stride.yaml` | AG_PRAXIS, committed before any model trained | 2026-08-11 |
| `config/shap_capec_map.yaml` | AG_PRAXIS, committed before any model trained | 2026-08-11 |
| `data/raw/attributions.json` | AG_PRAXIS NB09a output | 2026-08-13, git 281326e |
| `data/raw/threat_mapping.json` | AG_PRAXIS NB09b output | 2026-08-17, git 6912da6 |

The assignment rule this analysis audits (`analysis/assign.py`) is a line-for-line
reimplementation of the `assign()` function in `AG_PRAXIS_NB09b_threat_mapping.ipynb`,
cell 6, copied on 2026-10-01 for independent verification. It is not altered.

This repository makes no claim on, and does not restate, H1 or H2 or any other finding
of AG_PRAXIS. It examines one reported result from that praxis — H3's semantic
agreement figure (9/18) — and asks a question the praxis was not designed to answer:
whether the mapping *rule itself* is structurally biased, independent of model quality
or attribution values.
