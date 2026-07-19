# Windows Registry Monitoring System

A Python project to monitor the Windows Registry for suspicious changes. It checks for new, modified, or deleted registry keys and compares them against known malware patterns. 

---

## Project Structure

```
Registry_Monitor_System/
│
├── src/
│   ├── config.py              # Configuration file
│   ├── malware_patterns.py    # List of malware patterns to check against
│   ├── registry_monitor.py    # Main script to run
│   ├── report_generator.py    # Script to create PDF and TXT reports
│   ├── registry_baseline.json # Saved registry state
│   └── logs/
│       ├── registry_monitor.log   # Log file for all scans
│       └── registry_alerts.log    # Log file for warnings only
│
├── reports/
│   ├── registry_report.pdf    # PDF output of the session
│   ├── registry_report.txt    # Text output of the session
│   └── session_events.json    # Temporary file for report generation
|
├── requirements.txt           # Required libraries (reportlab)
└── README.md                  # This file
```

---

## How to Run

### Requirements
- Windows OS
- Python 3
- **Run Command Prompt as Administrator** (needed to read HKLM registry keys)
- Install requirements: `pip install -r requirements.txt`

### 1. Normal Monitoring
Runs every 10 seconds to check for changes.
```cmd
cd src
python registry_monitor.py
```

### 2. Create a New Baseline
If you want to reset the saved registry state, run this:
```cmd
python registry_monitor.py --rebaseline
```

### 3. Run Only Once
If you just want to do one scan and close it:
```cmd
python registry_monitor.py --once
```

### 4. Change Scan Interval
Change how often it scans (e.g., 30 seconds):
```cmd
python registry_monitor.py --interval 30
```

### 5. Integrity Check
Check if anything changed since the last baseline, without monitoring continuously:
```cmd
python registry_monitor.py --integrity
```

### 6. Generate Report
Creates a PDF and text file of the last session:
```cmd
python registry_monitor.py --report
```

---

## What it Monitors

The script monitors several important registry keys that malware often uses, such as:
- Startup programs (Run and RunOnce keys)
- Windows Defender and Firewall settings
- User Account Control (UAC) settings
- Winlogon
- Safe Mode settings

If it finds a change, it will check `malware_patterns.py` to see if the change matches known bad behavior (like adding a suspicious executable to the Run key).

---

## Example Output

When a change is detected, it will print something like this in the console:

```
--------------------------------------------------
[!] NEW ENTRY DETECTED
--------------------------------------------------
Time: 2026-05-03 14:22:11
Risk: CRITICAL
Path: HKCU\Software\Microsoft\Windows\CurrentVersion\Run
Name: TestMalware
New Value: C:\Users\User\AppData\Roaming\malware.exe

MALWARE WARNING: CRITICAL
Category: PERSISTENCE
Technique: Boot or Logon Autostart Execution (T1547.001)
Details: Suspicious path added to Run key. Malware uses this to start automatically.
Action: Check the executable file. Upload to VirusTotal.
--------------------------------------------------
```

---


