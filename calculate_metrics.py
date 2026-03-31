import os
import re
import json

ALERT_CATEGORIES = [
    "Data Exfiltration Anomaly",
    "DNS Tunneling Anomaly",
    "EDR",
    "Suspicious Azure Network Activity",
    "Suspicious Login",
    "Suspicious PowerShell Script",
    "Threat Intelligence (Company Logo Detection)",
    "Threat Intelligence (Company Mention in Potentially Leaked Documents)",
]


def parse_filename(filename):
    """
    Extract ground truth label and alert category from filename.

    Filename format: <Category>_HP_alert-N_investigation_notes.json
                  or <Category>_LP_alert-N_investigation_notes.json

    Ground truth = HP or LP embedded in the filename.
    Category     = everything before _HP_ or _LP_.

    Returns (ground_truth, category) or (None, None) if not parseable.
    """
    fn = os.path.basename(filename)

    match = re.search(r'_(HP|LP)_alert-\d+', fn, re.IGNORECASE)
    if not match:
        return None, None

    ground_truth = match.group(1).upper()

    raw_prefix = fn[:match.start()].rstrip("_")
    category = raw_prefix.replace("_", " ")

    return ground_truth, category


def get_predicted(filepath):
    """
    Read the classification field from an investigation notes JSON file.
    Returns HP or LP.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
        classification = data.get("classification", "").strip().upper()
        if classification in ("HP", "LP"):
            return classification
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def process_run_folder(run_folder_path):
    """
    Walk a run folder and compute confusion matrix values overall
    and per alert category.
    Ground truth is read from the filename (_HP_ or _LP_).
    Prediction is read from the classification field in the JSON file.
    """
    overall = {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "total": 0}
    per_category = {}

    for root, dirs, files in os.walk(run_folder_path):
        for filename in sorted(files):
            if not filename.endswith("_investigation_notes.json"):
                continue

            filepath = os.path.join(root, filename)
            ground_truth, category = parse_filename(filename)
            predicted = get_predicted(filepath)

            if not ground_truth:
                print(f"  WARNING: Could not parse ground truth from filename: {filename}")
                continue
            if not predicted:
                print(f"  WARNING: Could not read prediction from: {filename}")
                continue

            if category not in per_category:
                per_category[category] = {"TP": 0, "TN": 0, "FP": 0, "FN": 0, "total": 0}

            if ground_truth == "HP" and predicted == "HP":
                result = "TP"
            elif ground_truth == "LP" and predicted == "LP":
                result = "TN"
            elif ground_truth == "LP" and predicted == "HP":
                result = "FP"
            elif ground_truth == "HP" and predicted == "LP":
                result = "FN"
            else:
                continue

            overall[result] += 1
            overall["total"] += 1
            per_category[category][result] += 1
            per_category[category]["total"] += 1

    return overall, per_category


def compute_metrics(tp, tn, fp, fn):
    """Compute all classification metrics from confusion matrix values."""
    total = tp + tn + fp + fn
    metrics = {}

    metrics["accuracy"]  = round((tp + tn) / total * 100, 2)  if total > 0       else 0
    metrics["precision"] = round(tp / (tp + fp) * 100, 2)     if (tp + fp) > 0   else 0
    metrics["recall"]    = round(tp / (tp + fn) * 100, 2)     if (tp + fn) > 0   else 0
    metrics["fpr"]       = round(fp / (fp + tn) * 100, 2)     if (fp + tn) > 0   else 0
    metrics["fnr"]       = round(fn / (fn + tp) * 100, 2)     if (fn + tp) > 0   else 0

    p = metrics["precision"] / 100
    r = metrics["recall"] / 100
    metrics["f1"] = round(2 * p * r / (p + r) * 100, 2)       if (p + r) > 0     else 0

    return metrics


def print_results(folder_name, overall, per_category):
    """Print confusion matrix, derived metrics and per-category breakdown."""
    tp = overall["TP"]
    tn = overall["TN"]
    fp = overall["FP"]
    fn = overall["FN"]
    total = overall["total"]

    metrics = compute_metrics(tp, tn, fp, fn)

    print(f"\n{'=' * 65}")
    print(f"  {folder_name}")
    print(f"{'=' * 65}")

    print(f"\n  Confusion Matrix (HP = positive class):")
    print(f"  {'':25} {'Classified LP':>14} {'Classified HP':>14}")
    print(f"  {'Ground Truth LP':25} {'TN = ' + str(tn):>14} {'FP = ' + str(fp):>14}")
    print(f"  {'Ground Truth HP':25} {'FN = ' + str(fn):>14} {'TP = ' + str(tp):>14}")
    print(f"  Total alerts: {total}")

    print(f"\n  Derived Metrics:")
    print(f"  Accuracy  = (TP + TN) / total     = ({tp} + {tn}) / {total}            = {metrics['accuracy']}%")
    print(f"  Precision = TP / (TP + FP)         = {tp} / ({tp} + {fp})              = {metrics['precision']}%")
    print(f"  Recall    = TP / (TP + FN)         = {tp} / ({tp} + {fn})              = {metrics['recall']}%")
    print(f"  FPR       = FP / (FP + TN)         = {fp} / ({fp} + {tn})              = {metrics['fpr']}%")
    print(f"  FNR       = FN / (FN + TP)         = {fn} / ({fn} + {tp})              = {metrics['fnr']}%")
    p = metrics["precision"] / 100
    r = metrics["recall"] / 100
    print(f"  F1        = 2*(P*R)/(P+R)          = 2*({metrics['precision']/100:.4f}*{r:.4f})/({metrics['precision']/100:.4f}+{r:.4f}) = {metrics['f1']}%")

    print(f"\n  Per-Category Breakdown:")
    print(f"  {'Category':<60} {'TP':>4} {'TN':>4} {'FP':>4} {'FN':>4} {'Acc%':>6} {'FNR%':>6}")
    print(f"  {'-' * 92}")

    for cat in ALERT_CATEGORIES:
        if cat in per_category:
            c = per_category[cat]
            m = compute_metrics(c["TP"], c["TN"], c["FP"], c["FN"])
            print(
                f"  {cat:<60} {c['TP']:>4} {c['TN']:>4} {c['FP']:>4} {c['FN']:>4} "
                f"{m['accuracy']:>6} {m['fnr']:>6}"
            )

    unrecognised = [c for c in per_category if c not in ALERT_CATEGORIES]
    if unrecognised:
        print(f"\n  Unrecognised categories (check filename format):")
        for c in unrecognised:
            print(f"    - '{c}': {per_category[c]}")


def process_exported_results(exported_results_path):
    """
    Process all run folders inside exported_results starting with '6 -'.
    """
    all_results = {}

    run_folders = sorted([
        d for d in os.listdir(exported_results_path)
        if d.startswith("6 -") and
        os.path.isdir(os.path.join(exported_results_path, d))
    ])

    if not run_folders:
        print(f"No folders starting with '6 -' found in: {exported_results_path}")
        return

    for folder_name in run_folders:
        folder_path = os.path.join(exported_results_path, folder_name)
        overall, per_category = process_run_folder(folder_path)
        print_results(folder_name, overall, per_category)

        metrics = compute_metrics(
            overall["TP"], overall["TN"], overall["FP"], overall["FN"]
        )
        all_results[folder_name] = {
            "confusion_matrix": overall,
            "metrics": metrics,
            "per_category": {
                cat: {
                    "counts": per_category[cat],
                    "metrics": compute_metrics(
                        per_category[cat]["TP"],
                        per_category[cat]["TN"],
                        per_category[cat]["FP"],
                        per_category[cat]["FN"]
                    )
                }
                for cat in per_category
            }
        }

    print(f"\n{'=' * 95}")
    print("  CROSS-CONFIGURATION SUMMARY")
    print(f"{'=' * 95}")
    print(f"  {'Run':<45} {'Acc%':>6} {'Prec%':>6} {'Rec%':>6} {'F1%':>6} {'FPR%':>6} {'FNR%':>6}")
    print(f"  {'-' * 83}")
    for folder_name, data in all_results.items():
        m = data["metrics"]
        print(
            f"  {folder_name:<45} {m['accuracy']:>6} {m['precision']:>6} "
            f"{m['recall']:>6} {m['f1']:>6} {m['fpr']:>6} {m['fnr']:>6}"
        )
    print(f"{'=' * 95}")

    report_path = os.path.join(exported_results_path, "classification_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nFull report saved to: {report_path}")


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python calculate_metrics.py <path_to_exported_results>")
        print("Example: python calculate_metrics.py ./exported_results")
        sys.exit(1)

    exported_results_path = sys.argv[1]

    if not os.path.isdir(exported_results_path):
        print(f"Error: Directory not found: {exported_results_path}")
        sys.exit(1)

    process_exported_results(exported_results_path)