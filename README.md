# Structural Bias in Attribution-to-Taxonomy Mapping Rules

Standalone paper project, separate from the AG_PRAXIS doctoral praxis. See
`data/PROVENANCE.md` for exactly what was copied from AG_PRAXIS and why this is
independent work rather than a restatement of it.

## Question

AG_PRAXIS's H3 maps SHAP feature attributions to CAPEC attack patterns and then to
STRIDE threat categories, scoring 9/18 semantic agreement against documented attack
semantics (below the 0.667 majority-class baseline). This project asks: is that low
agreement a property of the detection model, or a property of the mapping rule itself?

## Finding (status: structural claim verified; model-level confirmation pending)

The mass-summation assignment rule gives STRIDE categories with more feature-to-CAPEC
entries in the config a multiplicative advantage, independent of any attribution
value. Information Disclosure holds 17 of 29 feature-to-CAPEC entries (59%) while
representing 4 of 18 ground-truth classes (22%); Tampering and Spoofing each hold
exactly 1 entry. Run `analysis/audit_mapping_bias.py` to reproduce.

Cross-checked against AG_PRAXIS's recorded disagreements (9 of 18 classes): all 9
resolve to one of three config-structural mechanisms, using only the top-5 features
AG_PRAXIS already reported per class. See `results/disagreement_mechanisms.csv`.

## What's verified vs. what isn't

- **Verified, from committed config files alone:** the entry-density imbalance, and
  that every one of the 9 known disagreements is consistent with it.
- **Not yet verified:** that attribution *mass* (not just presence) actually drove
  each assignment this way. That needs AG_PRAXIS's `attributions_seed_*.npz` files
  (ranks 6-10 and raw SHAP values), which are not in this repository.

## Structure

- `config/` — the three AG_PRAXIS mapping/ground-truth files (read-only inputs)
- `data/raw/` — AG_PRAXIS's NB09a/NB09b output artifacts (read-only inputs)
- `analysis/audit_mapping_bias.py` — independent reimplementation of the audit
- `results/` — generated tables (entry density, multi-candidate features, per-class
  disagreement mechanisms)
- `DECISIONS.md` — append-only log of what was checked and when

## Reproduce

```
pip install pyyaml
python3 analysis/audit_mapping_bias.py
```
