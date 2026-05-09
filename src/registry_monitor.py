import winreg
import time
import json
import os
import logging
import hashlib
import argparse
import sys
from datetime import datetime

from config import (
    BASELINE_FILE, LOG_FILE, ALERT_LOG_FILE, REPORTS_DIR,
    MONITORED_KEYS, HIVE_NAMES, RISK_COLORS, DEFAULT_POLL_INTERVAL,
    MAX_ALERTS_PER_SESSION,
)
from malware_patterns import RegistryChange, analyze_change, severity_score

# Logging Setup

logging.basicConfig(level=logging.DEBUG)

general_logger = logging.getLogger("registry_monitor")
general_logger.setLevel(logging.DEBUG)
general_logger.handlers = []

# log to file
fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setLevel(logging.DEBUG)

# log to console (stdout)
try:
    ch = logging.StreamHandler(
        open(sys.stdout.fileno(), mode='w', encoding='utf-8', closefd=False)
    )
except Exception:
    ch = logging.StreamHandler(sys.stdout)
ch.setLevel(logging.INFO)

formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s")
fh.setFormatter(formatter)
ch.setFormatter(formatter)
general_logger.addHandler(fh)
general_logger.addHandler(ch)

alert_logger = logging.getLogger("registry_alerts")
alert_logger.setLevel(logging.WARNING)
ah = logging.FileHandler(ALERT_LOG_FILE, encoding="utf-8")
ah.setFormatter(formatter)
alert_logger.addHandler(ah)

# Helper Functions

def get_hive_name(hkey):
    return HIVE_NAMES.get(hkey, str(hkey))

def get_full_path(hkey, subkey):
    return f"{get_hive_name(hkey)}\\{subkey}"

def get_sha256(text):
    # SHA-256 checksum for integrity checking
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()

def colorize(text, color_key):
    # print colored text in terminal
    if not sys.stdout.isatty():
        return text
    c = RISK_COLORS.get(color_key, "")
    r = RISK_COLORS["RESET"]
    return f"{c}{text}{r}"

# Registry Reader

def read_key_values(hkey, subkey):
    # reads all values from a registry key
    values = {}
    try:
        key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        i = 0
        while True:
            try:
                name, value, vtype = winreg.EnumValue(key, i)
                display_name = name if name else "(Default)"
                data_str = str(value)
                values[display_name] = {
                    "data": data_str,
                    "type": vtype,
                    "checksum": get_sha256(data_str),
                }
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)

    except FileNotFoundError:
        pass  # key doesn't exist on this system

    except PermissionError:
        general_logger.warning(
            "Permission denied: %s -- Run as Administrator",
            get_full_path(hkey, subkey)
        )
    except Exception as e:
        general_logger.error("Error reading %s: %s", subkey, e)

    return values


def read_subkeys(hkey, subkey):
    # returns list of child key names
    names = []
    try:
        key = winreg.OpenKey(hkey, subkey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        i = 0
        while True:
            try:
                names.append(winreg.EnumKey(key, i))
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except Exception:
        pass
    return names

# Session Statistics

class SessionStats:
    def __init__(self):
        self.total_changes = 0
        self.new_entries = 0
        self.modified_entries = 0
        self.deleted_entries = 0
        self.malware_alerts = 0
        self.critical_alerts = 0
        self.scan_count = 0
        self.start_time = datetime.now()
        self.alert_events = []

    def record_change(self, change_type, path, name, old_val, new_val, pattern_matches):
        self.total_changes += 1
        if change_type == "NEW":
            self.new_entries += 1
        elif change_type == "MODIFIED":
            self.modified_entries += 1
        elif change_type == "DELETED":
            self.deleted_entries += 1

        if pattern_matches:
            self.malware_alerts += len(pattern_matches)
            for pm in pattern_matches:
                if pm.severity == "CRITICAL":
                    self.critical_alerts += 1

        # save event info for report
        event = {
            "timestamp": datetime.now().isoformat(),
            "change_type": change_type,
            "key_path": path,
            "value_name": name,
            "old_value": old_val,
            "new_value": new_val,
            "patterns": [],
        }
        for pm in pattern_matches:
            event["patterns"].append({
                "severity": pm.severity,
                "category": pm.category,
                "technique": pm.technique,
                "technique_id": pm.technique_id,
                "description": pm.description,
                "recommendation": pm.recommendation,
            })
        self.alert_events.append(event)

    def print_summary(self):
        duration = datetime.now() - self.start_time
        print("\n" + "=" * 55)
        print(colorize("  SESSION SUMMARY", "INFO"))
        print("=" * 55)
        print(f"  Duration        : {str(duration).split('.')[0]}")
        print(f"  Total Scans     : {self.scan_count}")
        print(f"  Total Changes   : {self.total_changes}")
        print(f"    -> New        : {self.new_entries}")
        print(f"    -> Modified   : {self.modified_entries}")
        print(f"    -> Deleted    : {self.deleted_entries}")
        print(f"  Malware Alerts  : {self.malware_alerts}")
        print(f"  Critical Alerts : {colorize(str(self.critical_alerts), 'CRITICAL')}")
        print("=" * 55 + "\n")


# global stats for the session
stats = SessionStats()

# Baseline Management

def capture_baseline():
    # take a snapshot of all monitored registry keys
    general_logger.info("Capturing registry baseline snapshot...")

    baseline = {}
    for hkey, subkey, description, risk in MONITORED_KEYS:
        path = get_full_path(hkey, subkey)
        values = read_key_values(hkey, subkey)
        subkeys = read_subkeys(hkey, subkey)

        baseline[path] = {
            "values": values,
            "subkeys": subkeys,
            "description": description,
            "risk_level": risk,
            "captured_at": datetime.now().isoformat(),
        }
        general_logger.info("Captured: %s  (%d values)", path, len(values))

    os.makedirs(os.path.dirname(BASELINE_FILE), exist_ok=True)
    with open(BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(baseline, f, indent=4)

    general_logger.info("Baseline saved to %s", BASELINE_FILE)
    return baseline


def load_baseline():
    # load baseline from file, or create one if missing
    if not os.path.exists(BASELINE_FILE):
        general_logger.info("No baseline found. Creating one now...")
        return capture_baseline()

    with open(BASELINE_FILE, "r", encoding="utf-8") as f:
        baseline = json.load(f)

    general_logger.info("Baseline loaded from %s  (%d keys)", BASELINE_FILE, len(baseline))
    return baseline

# Alert Output

def emit_alert(change_type, path, name, old_val, new_val, risk_level, pattern_matches):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sep = "-" * 60

    labels = {
        "NEW":      "[!] NEW ENTRY DETECTED",
        "MODIFIED": "[!] ENTRY MODIFIED",
        "DELETED":  "[!] ENTRY DELETED",
    }
    label = labels.get(change_type, f"[!] CHANGE ({change_type})")

    print()
    print(colorize(sep, risk_level))
    print(colorize(f"  {label}", risk_level))
    print(colorize(sep, risk_level))
    print(f"  Timestamp  : {ts}")
    print(f"  Risk Level : {colorize(risk_level, risk_level)}")
    print(f"  Key Path   : {path}")
    print(f"  Value Name : {name}")

    if old_val is not None:
        print(f"  Old Value  : {old_val}")
    if new_val is not None:
        print(f"  New Value  : {new_val}")

    if pattern_matches:
        sorted_matches = sorted(pattern_matches, key=lambda m: severity_score(m.severity), reverse=True)
        for pm in sorted_matches:
            print()
            print(colorize(f"  [MALWARE PATTERN MATCH] [{pm.severity}]", "CRITICAL"))
            print(f"     Category     : {pm.category}")
            print(f"     MITRE Tactic : {pm.technique}  ({pm.technique_id})")
            print(f"     Description  : {pm.description}")
            print(colorize(f"     Action Needed: {pm.recommendation}", "HIGH"))

    print(colorize(sep, risk_level))

    log_line = f"[{change_type}] {path} -> {name}  (old={old_val!r}, new={new_val!r})"
    general_logger.warning(log_line)
    alert_logger.warning(log_line)

    for pm in pattern_matches:
        alert_logger.warning(
            "  PATTERN: [%s] %s (%s) -- %s",
            pm.severity, pm.technique, pm.technique_id, pm.description
        )

    stats.record_change(change_type, path, name, old_val, new_val, pattern_matches)

# Change Detection

def check_for_changes(baseline):
    changes_found = False

    for hkey, subkey, description, risk_level in MONITORED_KEYS:
        path = get_full_path(hkey, subkey)
        current = read_key_values(hkey, subkey)

        if path not in baseline:
            baseline[path] = {
                "values": {},
                "subkeys": [],
                "description": description,
                "risk_level": risk_level,
                "captured_at": datetime.now().isoformat(),
            }

        baseline_values = baseline[path].get("values", {})

        # check for new or modified values
        for name, info in current.items():
            new_data = info["data"]
            if name not in baseline_values:
                change = RegistryChange(change_type="NEW", key_path=path, value_name=name, new_value=new_data)
                matches = analyze_change(change)
                emit_alert("NEW", path, name, None, new_data, risk_level, matches)
                baseline_values[name] = info
                changes_found = True

            elif baseline_values[name]["checksum"] != info["checksum"]:
                old_data = baseline_values[name]["data"]
                change = RegistryChange(change_type="MODIFIED", key_path=path, value_name=name, old_value=old_data, new_value=new_data)
                matches = analyze_change(change)
                emit_alert("MODIFIED", path, name, old_data, new_data, risk_level, matches)
                baseline_values[name] = info
                changes_found = True

        # check for deleted values
        deleted = [n for n in baseline_values if n not in current]
        for name in deleted:
            old_data = baseline_values[name]["data"]
            change = RegistryChange(change_type="DELETED", key_path=path, value_name=name, old_value=old_data)
            matches = analyze_change(change)
            emit_alert("DELETED", path, name, old_data, None, risk_level, matches)
            del baseline_values[name]
            changes_found = True

    return changes_found

# Main Monitor Loop

def run_monitor(interval, once=False):
    general_logger.info("Registry Monitor started.")
    general_logger.info("Poll interval : %d seconds", interval)
    general_logger.info("Monitored keys: %d", len(MONITORED_KEYS))
    general_logger.info("Press Ctrl+C to stop.")

    baseline = load_baseline()

    try:
        while True:
            stats.scan_count += 1
            general_logger.info("[Scan #%03d] Checking registry...", stats.scan_count)

            changed = check_for_changes(baseline)

            if changed:
                with open(BASELINE_FILE, "w", encoding="utf-8") as f:
                    json.dump(baseline, f, indent=4)
                general_logger.info("Baseline updated after change(s) detected.")
            else:
                general_logger.info("[Scan #%03d] No changes detected.", stats.scan_count)

            if once:
                break

            if stats.total_changes >= MAX_ALERTS_PER_SESSION:
                general_logger.warning("Alert cap reached. Stopping to avoid log overflow.")
                break

            time.sleep(interval)

    except KeyboardInterrupt:
        general_logger.info("Monitor stopped by user (Ctrl+C).")

    finally:
        stats.print_summary()
        save_session_events()


def save_session_events():
    os.makedirs(REPORTS_DIR, exist_ok=True)
    out = os.path.join(REPORTS_DIR, "session_events.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump({
            "session_start": stats.start_time.isoformat(),
            "session_end": datetime.now().isoformat(),
            "total_scans": stats.scan_count,
            "total_changes": stats.total_changes,
            "new_entries": stats.new_entries,
            "modified_entries": stats.modified_entries,
            "deleted_entries": stats.deleted_entries,
            "malware_alerts": stats.malware_alerts,
            "critical_alerts": stats.critical_alerts,
            "events": stats.alert_events,
        }, f, indent=4)
    general_logger.info("Session events saved to %s", out)

# Integrity Check

def run_integrity_check():
    if not os.path.exists(BASELINE_FILE):
        general_logger.error("No baseline file found. Run with --rebaseline first.")
        return

    baseline = load_baseline()

    print("\n" + "=" * 60)
    print(colorize("  REGISTRY INTEGRITY CHECK REPORT", "INFO"))
    print(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    failures = []

    for hkey, subkey, description, risk in MONITORED_KEYS:
        path = get_full_path(hkey, subkey)
        current = read_key_values(hkey, subkey)
        saved = baseline.get(path, {}).get("values", {})

        key_ok = True

        for name, info in current.items():
            if name not in saved:
                msg = f"  [ADDED]    {path} -> {name} = {info['data']}"
                print(colorize(msg, "CRITICAL"))
                failures.append(msg)
                key_ok = False
            elif saved[name]["checksum"] != info["checksum"]:
                msg = (
                    f"  [MODIFIED] {path} -> {name}\n"
                    f"             Baseline : {saved[name]['data']}\n"
                    f"             Current  : {info['data']}"
                )
                print(colorize(msg, "HIGH"))
                failures.append(msg)
                key_ok = False

        for name in saved:
            if name not in current:
                msg = f"  [DELETED]  {path} -> {name}"
                print(colorize(msg, "HIGH"))
                failures.append(msg)
                key_ok = False

        status = colorize("[PASS]", "INFO") if key_ok else colorize("[FAIL]", "CRITICAL")
        print(f"  {status}  {path}")

    print("=" * 60)
    if failures:
        print(colorize(f"  INTEGRITY FAILURES: {len(failures)}", "CRITICAL"))
    else:
        print(colorize("  ALL MONITORED KEYS MATCH BASELINE -- SYSTEM CLEAN", "INFO"))
    print("=" * 60 + "\n")

# Argument Parser with custom --help

def print_help():
    # custom help message to show all commands clearly
    print("""
Windows Registry Monitoring System
Final Year Internship Project
==============================================

USAGE:
  python registry_monitor.py [command]

COMMANDS:
  (no flag)            Start monitoring the registry (default 10s interval)
  --rebaseline         Capture a fresh baseline snapshot, then start monitoring
  --interval SECONDS   Set how many seconds to wait between each scan (default: 10)
  --once               Do a single scan and exit (no loop)
  --integrity          Compare current registry against saved baseline and exit
  --report             Generate a PDF and TXT report from last session, then exit
  --help               Show this help message and exit

EXAMPLES:
  python registry_monitor.py
  python registry_monitor.py --rebaseline
  python registry_monitor.py --interval 30
  python registry_monitor.py --once
  python registry_monitor.py --integrity
  python registry_monitor.py --report

NOTES:
  - Run as Administrator to access HKLM registry keys
  - Baseline file is saved in src/registry_baseline.json
  - Logs are saved in src/registry_monitor.log and src/registry_alerts.log
  - Reports are saved in the reports/ folder

==============================================
""")


if __name__ == "__main__":
    # show custom help if --help or -h
    if "--help" in sys.argv or "-h" in sys.argv:
        print_help()
        sys.exit(0)

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--rebaseline", action="store_true")
    parser.add_argument("--interval", type=int, default=DEFAULT_POLL_INTERVAL)
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--integrity", action="store_true")
    parser.add_argument("--report", action="store_true")

    args = parser.parse_args()

    if args.integrity:
        run_integrity_check()
        sys.exit(0)

    if args.report:
        from report_generator import generate_report
        generate_report()
        sys.exit(0)

    if args.rebaseline:
        capture_baseline()

    run_monitor(interval=args.interval, once=args.once)
