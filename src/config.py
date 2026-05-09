import os
import winreg

# Paths setup
SRC_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_DIR = os.path.dirname(SRC_DIR)

# Folders for outputs
REPORTS_DIR = os.path.join(PROJECT_DIR, "reports")
LOGS_DIR = os.path.join(SRC_DIR, "logs")  # separate logs folder inside src/

# Create the logs folder if it doesn't exist yet
os.makedirs(LOGS_DIR, exist_ok=True)

# Files
BASELINE_FILE = os.path.join(SRC_DIR, "registry_baseline.json")
LOG_FILE = os.path.join(LOGS_DIR, "registry_monitor.log")
ALERT_LOG_FILE = os.path.join(LOGS_DIR, "registry_alerts.log")
REPORT_PDF = os.path.join(REPORTS_DIR, "registry_report.pdf")
REPORT_TXT = os.path.join(REPORTS_DIR, "registry_report.txt")

# Monitor settings
DEFAULT_POLL_INTERVAL = 10  # default scan time in seconds
MAX_ALERTS_PER_SESSION = 500  # don't flood the logs

# List of registry keys to monitor
MONITORED_KEYS = [
    # Autorun stuff
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM Autorun", "CRITICAL"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM RunOnce", "CRITICAL"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU Autorun", "CRITICAL"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU RunOnce", "CRITICAL"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon", "Winlogon hijacking", "CRITICAL"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServices", "RunServices", "HIGH"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunServicesOnce", "RunServicesOnce", "HIGH"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "IFEO Injection", "CRITICAL"),

    # Defender & Security
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender", "Defender policy", "CRITICAL"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection", "Defender Real-Time", "CRITICAL"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows Defender\Features", "Defender features", "HIGH"),

    # Firewall
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile", "Firewall Standard", "HIGH"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile", "Firewall Domain", "HIGH"),

    # UAC
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System", "UAC policies", "CRITICAL"),

    # System Config
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\SafeBoot", "Safe Boot config", "HIGH"),
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services", "System services", "MEDIUM"),

    # Network
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Internet Settings", "Internet Settings", "HIGH"),

    # Extensions
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", "CRITICAL"),
    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", "Browser Helper Objects", "HIGH"),

    # LSA
    (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Lsa", "LSA security", "CRITICAL"),
]

HIVE_NAMES = {
    winreg.HKEY_LOCAL_MACHINE: "HKLM",
    winreg.HKEY_CURRENT_USER: "HKCU",
    winreg.HKEY_CLASSES_ROOT: "HKCR",
    winreg.HKEY_USERS: "HKU",
    winreg.HKEY_CURRENT_CONFIG: "HKCC",
}

RISK_COLORS = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[96m",
    "INFO": "\033[92m",
    "RESET": "\033[0m",
}
