import os
import re
import json

PLAYBOOK_TOOLS = {
    "excessive_downloads.json":              {"lookup_users", "get_recent_events", "get_recent_similar_alerts"},
    "suspicious_dns_queries.json":           {"get_domain_age", "get_recent_events", "get_recent_similar_alerts"},
    "EDR_anti_tampering.json":               {"get_recent_events", "get_recent_similar_alerts"},
    "EDR_identity_alerts.json":              {"get_recent_events"},
    "EDR_malware_alerts.json":               {"lookup_users", "check_hash_reputation", "get_recent_events", "get_recent_similar_alerts", "check_ip_reputation"},
    "logo_abuse_detection.json":             {"check_ip_reputation", "get_recent_similar_alerts"},
    "potentially_leaked_document.json":      {"get_recent_similar_alerts"},
    "suspicious_cloud_network_activity.json":{"lookup_users", "get_recent_events", "get_recent_similar_alerts"},
    "suspicious_login.json":                 {"check_ip_reputation", "get_recent_events", "get_recent_similar_alerts"},
    "suspicious_powershell.json":            {"check_hash_reputation", "check_ip_reputation", "get_recent_events", "get_recent_similar_alerts"},
}


FILENAME_PREFIX_PLAYBOOK = {
    "Data Exfiltration Anomaly":                                              "excessive_downloads.json",
    "DNS Tunneling Anomaly":                                                  "suspicious_dns_queries.json",
    "Suspicious Azure Network Activity":                                      "suspicious_cloud_network_activity.json",
    "Suspicious Login":                                                       "suspicious_login.json",
    "Suspicious PowerShell Script":                                           "suspicious_powershell.json",
    "Threat Intelligence (Company Logo Detection)":                           "logo_abuse_detection.json",
    "Threat Intelligence (Company Mention in Potentially Leaked Documents)":  "potentially_leaked_document.json",
    "EDR":                                                                    None,  # handled separately
}

EDR_ALERT_PLAYBOOK = {
    "HP_alert-1": "EDR_malware_alerts.json",
    "HP_alert-2": "EDR_malware_alerts.json",
    "HP_alert-3": "EDR_malware_alerts.json",
    "HP_alert-4": "EDR_anti_tampering.json",
    "HP_alert-5": "EDR_malware_alerts.json",
    "LP_alert-1": "EDR_malware_alerts.json",
    "LP_alert-2": "EDR_identity_alerts.json",
    "LP_alert-3": "EDR_malware_alerts.json",
    "LP_alert-4": "EDR_malware_alerts.json",
    "LP_alert-5": "EDR_malware_alerts.json",
}

_EXC = {}

def _ex(prefix, alert_key, tools):
    key = f"{prefix}|{alert_key}"
    _EXC.setdefault(key, set()).update(tools)

for _k in ["HP_alert-1", "HP_alert-2", "HP_alert-3", "HP_alert-5",
           "LP_alert-1", "LP_alert-3", "LP_alert-4", "LP_alert-5"]:
    _ex("EDR", _k, {"check_ip_reputation"})

_ex("EDR", "HP_alert-2", {"check_hash_reputation"})

for _k in ["LP_alert-1", "LP_alert-2"]:
    _ex("Suspicious Azure Network Activity", _k, {"lookup_users"})

for _k in ["HP_alert-1", "HP_alert-2", "HP_alert-3", "HP_alert-4", "HP_alert-5",
           "LP_alert-1", "LP_alert-2", "LP_alert-3", "LP_alert-4", "LP_alert-5",
           "LP_alert-10"]:
    _ex("Suspicious PowerShell Script", _k, {"check_hash_reputation"})

for _k in ["HP_alert-1", "HP_alert-3", "HP_alert-4", "HP_alert-5",
           "HP_alert-8", "HP_alert-9",
           "LP_alert-1", "LP_alert-2", "LP_alert-3", "LP_alert-4", "LP_alert-5",
           "LP_alert-6", "LP_alert-7", "LP_alert-8", "LP_alert-9", "LP_alert-10"]:
    _ex("Suspicious PowerShell Script", _k, {"check_ip_reputation"})

TOOL_EXCEPTIONS = _EXC

EDR_PLAYBOOKS = {"EDR_malware_alerts.json", "EDR_anti_tampering.json", "EDR_identity_alerts.json"}

def extract_tools_called(log_text):
    """Extract all tool names actually invoked from a debug log."""
    pattern = re.compile(r'\[TOOL CALL\]\s*\nTool:\s*(\S+)', re.MULTILINE)
    return set(pattern.findall(log_text))


def parse_filename(filename):
    """
    Parse a debug log filename into (filename_prefix, alert_key).

    Filename format:  <Category>_<HP|LP>_alert-<N>_debug.log
    Example:          Suspicious_PowerShell_Script_HP_alert-1_debug.log
                      EDR_HP_alert-4_debug.log

    Returns:
        filename_prefix  — category string matching FILENAME_PREFIX_PLAYBOOK keys
        alert_key        — e.g. "HP_alert-1"
    """
    fn = os.path.basename(filename)

    key_match = re.search(r'(HP|LP)_alert-(\d+)', fn, re.IGNORECASE)
    if not key_match:
        return None, None

    alert_key = f"{key_match.group(1).upper()}_alert-{key_match.group(2)}"

    raw_prefix = fn[:key_match.start()].rstrip("_")
    filename_prefix = raw_prefix.replace("_", " ")

    return filename_prefix, alert_key


def get_playbook(filename_prefix, alert_key, log_text):
    """
    Determine the playbook for this alert.
    Priority: filename prefix → EDR sub-mapping → log fallback.
    """
    if filename_prefix == "EDR":
        return EDR_ALERT_PLAYBOOK.get(alert_key)

    playbook = FILENAME_PREFIX_PLAYBOOK.get(filename_prefix)
    if playbook:
        return playbook

    pb_match = re.search(
        r'\[PLAYBOOK SELECTION\].*?Selected Playbook:\s*(\S+)',
        log_text, re.DOTALL
    )
    if pb_match:
        return pb_match.group(1).strip()

    return None


def get_expected_tools(filename, log_text):
    """
    Return (playbook, expected_tools, filename_prefix, alert_key).
    Expected tools are the base playbook tools minus any per-alert exceptions.
    All lookups use the filename — never the raw alert name from the log.
    """
    filename_prefix, alert_key = parse_filename(filename)

    if not alert_key:
        return "unknown", set(), filename_prefix or "", alert_key

    playbook = get_playbook(filename_prefix, alert_key, log_text)

    if not playbook:
        return "unknown", set(), filename_prefix or "", alert_key

    expected_tools = set(PLAYBOOK_TOOLS.get(playbook, set()))

    if playbook in EDR_PLAYBOOKS:
        exc_prefix = "EDR"
    else:
        exc_prefix = filename_prefix

    exc_key = f"{exc_prefix}|{alert_key}"
    if exc_key in TOOL_EXCEPTIONS:
        expected_tools -= TOOL_EXCEPTIONS[exc_key]

    return playbook, expected_tools, filename_prefix or "", alert_key


def process_run_folder(run_folder_path):
    """
    Walk a run folder, evaluate every debug log and compute TCR.
    General mode logs are skipped automatically.
    """
    results = {
        "folder": os.path.basename(run_folder_path),
        "total_alerts": 0,
        "compliant_alerts": 0,
        "non_compliant_alerts": 0,
        "tcr": 0.0,
        "details": []
    }

    for root, dirs, files in os.walk(run_folder_path):
        for filename in sorted(files):
            if not filename.endswith("_debug.log"):
                continue

            filepath = os.path.join(root, filename)
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                log_text = f.read()

            if ("General Triage Mode" in log_text or
                    "General Triage (No Playbook)" in log_text):
                continue

            playbook, expected_tools, filename_prefix, alert_key = get_expected_tools(
                filename, log_text
            )
            tools_called = extract_tools_called(log_text)
            missing_tools = expected_tools - tools_called
            extra_tools = tools_called - expected_tools
            is_compliant = len(missing_tools) == 0 and len(extra_tools) == 0

            results["total_alerts"] += 1
            if is_compliant:
                results["compliant_alerts"] += 1
            else:
                results["non_compliant_alerts"] += 1

            results["details"].append({
                "file": os.path.relpath(filepath, run_folder_path),
                "filename_prefix": filename_prefix,
                "alert_key": alert_key,
                "playbook": playbook,
                "expected_tools": sorted(expected_tools),
                "tools_called": sorted(tools_called),
                "missing_tools": sorted(missing_tools),
                "extra_tools": sorted(extra_tools),
                "compliant": is_compliant
            })

    if results["total_alerts"] > 0:
        results["tcr"] = round(
            results["compliant_alerts"] / results["total_alerts"] * 100, 2
        )

    return results


def process_exported_results(exported_results_path):
    """
    Process all run folders inside exported_results starting with '6 -'.
    """
    all_results = []

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
        print(f"\nProcessing: {folder_name}")
        result = process_run_folder(folder_path)
        all_results.append(result)

        print(f"  Total alerts (playbook mode): {result['total_alerts']}")
        print(f"  Compliant:                    {result['compliant_alerts']}")
        print(f"  Non-compliant:                {result['non_compliant_alerts']}")
        print(f"  TCR:                          {result['tcr']}%")

        non_compliant = [d for d in result["details"] if not d["compliant"]]
        if non_compliant:
            print(f"  Non-compliant alerts:")
            for d in non_compliant:
                print(f"    - {d['file']}")
                print(f"      Prefix:    {d['filename_prefix']} | {d['alert_key']}")
                print(f"      Playbook:  {d['playbook']}")
                print(f"      Expected:  {d['expected_tools']}")
                print(f"      Called:    {d['tools_called']}")
                print(f"      Missing:   {d['missing_tools']}")
                print(f"      Extra:     {d['extra_tools']}")

    print("\n" + "=" * 70)
    print("TCR SUMMARY")
    print("=" * 70)
    print(f"{'Run':<45} {'Total':>7} {'Comply':>7} {'TCR':>8}")
    print("-" * 70)
    for r in all_results:
        print(
            f"{r['folder']:<45} {r['total_alerts']:>7} "
            f"{r['compliant_alerts']:>7} {r['tcr']:>7}%"
        )
    print("=" * 70)

    report_path = os.path.join(exported_results_path, "tcr_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nFull report saved to: {report_path}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python calculate_tcr.py <path_to_exported_results>")
        print("Example: python calculate_tcr.py ./exported_results")
        sys.exit(1)

    exported_results_path = sys.argv[1]

    if not os.path.isdir(exported_results_path):
        print(f"Error: Directory not found: {exported_results_path}")
        sys.exit(1)

    process_exported_results(exported_results_path)