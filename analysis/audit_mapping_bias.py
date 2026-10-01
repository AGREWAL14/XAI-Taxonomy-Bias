"""
Independent audit of the SHAP-to-CAPEC-to-STRIDE mapping rule used in AG_PRAXIS H3.

This does NOT require the per-seed SHAP attribution vectors (the .npz files). The
finding this script establishes is a property of the committed config files alone:
the mass-summation assignment rule (reproduced below from NB09b cell 6) gives STRIDE
categories with more feature-to-CAPEC entries a structural multiplier advantage,
regardless of what the attribution values turn out to be.

It then cross-checks that structural prediction against the actual recorded
disagreements in threat_mapping.json, using only the top-5 features that artifact
already names per class (ranks 6-10 and raw magnitudes are not available here and
are not needed for the structural claim).

Run: python analysis/audit_mapping_bias.py
"""
import json
from collections import defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "config"
RAW = ROOT / "data" / "raw"
RESULTS = ROOT / "results"
RESULTS.mkdir(exist_ok=True)

FEATURE_MAP = yaml.safe_load((CONFIG / "shap_capec_map.yaml").read_text())
CAPEC_STRIDE = yaml.safe_load((CONFIG / "capec_stride.yaml").read_text())["mapping"]
GROUND_TRUTH = yaml.safe_load((CONFIG / "stride_ground_truth.yaml").read_text())
MAPPING = json.loads((RAW / "threat_mapping.json").read_text())


def capec_to_stride(capec_id):
    return CAPEC_STRIDE[capec_id]["stride"]


# ---------------------------------------------------------------------------
# Part 1 — structural entry density per STRIDE category, from the config alone.
# ---------------------------------------------------------------------------
entry_counts = defaultdict(int)
per_feature_entries = {}
for feature, entries in FEATURE_MAP["features"].items():
    strides = [capec_to_stride(e["capec"]) for e in entries]
    per_feature_entries[feature] = strides
    for s in strides:
        entry_counts[s] += 1

truth_class_counts = defaultdict(int)
for cls, v in GROUND_TRUTH["classes"].items():
    truth_class_counts[v["stride"]] += 1

print("=" * 80)
print("STRUCTURAL ENTRY DENSITY (from config files, no model output used)")
print("=" * 80)
header = f"{'STRIDE category':<24}{'feature->CAPEC entries':>24}{'ground-truth classes':>24}"
print(header)
with open(RESULTS / "entry_density.csv", "w") as f:
    f.write("stride_category,feature_capec_entries,ground_truth_classes\n")
    for stride in sorted(set(entry_counts) | set(truth_class_counts)):
        n_entries = entry_counts.get(stride, 0)
        n_classes = truth_class_counts.get(stride, 0)
        print(f"{stride:<24}{n_entries:>24}{n_classes:>24}")
        f.write(f"{stride},{n_entries},{n_classes}\n")
print()
print("Information Disclosure carries far more entries per its share of ground-truth")
print("classes than Denial of Service, Tampering, or Spoofing do. A feature ambiguous")
print("between two ID sub-patterns (e.g. a scan vs. a ping) gets its attribution mass")
print("counted toward ID twice; a feature mapping to one DoS pattern is counted once.")
print()

# ---------------------------------------------------------------------------
# Part 2 — per-feature multiplicity: how many STRIDE "votes" a feature casts.
# ---------------------------------------------------------------------------
multi_candidate = {f: s for f, s in per_feature_entries.items() if len(s) > 1}
print("=" * 80)
print("FEATURES THAT MAP TO MORE THAN ONE CAPEC PATTERN (candidate dilution)")
print("=" * 80)
with open(RESULTS / "multi_candidate_features.csv", "w") as f:
    f.write("feature,stride_targets\n")
    for feature, strides in multi_candidate.items():
        print(f"  {feature:<20} -> {strides}")
        f.write(f"{feature},\"{strides}\"\n")
print()

# ---------------------------------------------------------------------------
# Part 3 — cross-check against the recorded disagreements (sequence model, seed 42).
# ---------------------------------------------------------------------------
seq_result = next(r for r in MAPPING["h3"] if r["model"].startswith("sequence"))
disagreements = [row for row in seq_result["per_class"] if not row["agrees"]]

TAMPERING_ONLY_FEATURE = {"Header_Length"}  # only feature mapping to CAPEC-153
SPOOFING_ONLY_FEATURE = {"ARP"}             # only feature mapping to CAPEC-151
DOS_ONLY_VOLUME_FEATURES = {"Number", "Tot sum", "Weight", "Tot size"}


def classify_mechanism(row):
    top5 = [f.strip() for f in row["top_features"].split(",")]
    truth = row["truth"]
    assigned = row["assigned"]

    if truth == "Tampering" and not TAMPERING_ONLY_FEATURE & set(top5):
        return "single-route STRIDE category unreachable (Tampering has 1 feature in the whole map)"
    if truth == "Spoofing" and not SPOOFING_ONLY_FEATURE & set(top5):
        return "single-route STRIDE category unreachable (Spoofing has 1 feature in the whole map)"
    if assigned == "Denial of Service" and DOS_ONLY_VOLUME_FEATURES & set(top5) and truth != "Denial of Service":
        return "volume feature (Number/Tot sum/Weight/Tot size) is DoS-only in the config"
    if assigned == "Information Disclosure" and truth == "Denial of Service":
        ambiguous = [f for f in top5 if len(per_feature_entries.get(f, [])) > 1
                     and "Information Disclosure" in per_feature_entries.get(f, [])]
        if ambiguous:
            return f"multi-candidate ID dilution via {ambiguous}"
    return "mechanism not resolved from top-5 alone; ranks 6-10 needed"


print("=" * 80)
print("PER-CLASS DISAGREEMENT MECHANISM (sequence model, seed 42)")
print("=" * 80)
with open(RESULTS / "disagreement_mechanisms.csv", "w") as f:
    f.write("class,truth,assigned,top_5_features,mechanism\n")
    for row in disagreements:
        mech = classify_mechanism(row)
        print(f"  {row['class']:<28} truth={row['truth']:<22} assigned={row['assigned']:<22}")
        print(f"    top-5: {row['top_features']}")
        print(f"    mechanism: {mech}")
        print()
        f.write(f"{row['class']},{row['truth']},{row['assigned']},"
                f"\"{row['top_features']}\",\"{mech}\"\n")

n_resolved = sum(1 for row in disagreements if classify_mechanism(row) != "mechanism not resolved from top-5 alone; ranks 6-10 needed")
print(f"{n_resolved} of {len(disagreements)} disagreements resolve to a config-structural")
print("mechanism using only the top-5 features already on record. The remainder would")
print("need ranks 6-10 and raw magnitudes (the .npz files) to resolve with certainty.")
