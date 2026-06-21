#!/usr/bin/env python3
print("")
print("=" * 70)
print(""" 
    ██╗  ██╗██╗██████╗  █████╗ ███╗   ██╗
    ██║  ██║██║██╔══██╗██╔══██╗████╗  ██║
    ███████║██║██║  ██║███████║██╔██╗ ██║
    ██╔══██║██║██║  ██║██╔══██║██║╚██╗██║
    ██║  ██║██║██████╔╝██║  ██║██║ ╚████║
    ╚═╝  ╚═╝╚═╝╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
    By Hidan scripts v1.5
""")
print("=" * 70)

import os
import sys
import platform
import subprocess
import time
import datetime
from pathlib import Path

# ----------------------------- Color handling -----------------------------

class Color:
    WHITE = "\033[97m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    GRAY = "\033[90m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def enable_windows_ansi():
    """Enable ANSI escape code support on Windows cmd.exe."""
    if platform.system() == "Windows":
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
        except Exception:
            pass


def c(text, color):
    return f"{color}{text}{Color.RESET}"


def header(title):
    line = "=" * 70
    print(c(line, Color.CYAN))
    print(c(f" {title}", Color.CYAN + Color.BOLD))
    print(c(line, Color.CYAN))


def subheader(title):
    print()
    print(c(f"-- {title} --", Color.WHITE + Color.BOLD))


# ----------------------------- Helpers -----------------------------

SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".msi"}
EXECUTABLE_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".com", ".pif", ".gadget", ".msi"}

# Heuristic thresholds
RECENT_DAYS = 14
MAX_LIST = 250


def human_time(ts):
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "unknown"


def safe_walk(root, max_depth=6):
    """Walk a directory tree with a depth limit, skipping errors silently."""
    root = Path(root)
    if not root.exists():
        return
    root_depth = len(root.parts)
    try:
        for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
            depth = len(Path(dirpath).parts) - root_depth
            if depth >= max_depth:
                dirnames[:] = []
            for fname in filenames:
                yield Path(dirpath) / fname
    except Exception:
        return


def check_signature_windows(filepath):
    """Check if a Windows executable is signed using signtool."""
    try:
        result = subprocess.run(
            ["signtool", "verify", "/pa", "/v", str(filepath)],
            capture_output=True, text=True, timeout=10
        )
        if "Successfully verified" in result.stdout:
            return "Signed"
        elif "SignTool Error" in result.stdout:
            return "Not signed"
        else:
            return "Unknown"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        # Try alternative method using PowerShell
        try:
            ps_cmd = f'Get-AuthenticodeSignature -FilePath "{filepath}" | Select-Object -ExpandProperty SignerCertificate'
            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=10
            )
            if result.stdout.strip():
                return "Signed"
            else:
                return "Not signed"
        except Exception:
            return "Unknown"
    except Exception:
        return "Unknown"


def get_file_info(filepath):
    """Get file information including size and modification time."""
    try:
        stat = filepath.stat()
        size = stat.st_size
        mtime = stat.st_mtime
        return size, mtime
    except Exception:
        return 0, 0


# ----------------------------- Section 1: System Info -----------------------------

def get_install_date_windows():
    try:
        result = subprocess.run(
            ["systeminfo"], capture_output=True, text=True, timeout=20
        )
        for line in result.stdout.splitlines():
            if "Original Install Date" in line:
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    # Fallback: registry InstallDate via reg query
    try:
        result = subprocess.run(
            ["reg", "query", r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion",
             "/v", "InstallDate"],
            capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.splitlines():
            if "InstallDate" in line:
                hexval = line.strip().split()[-1]
                ts = int(hexval, 16)
                return human_time(ts)
    except Exception:
        pass
    return "Unavailable"


def get_install_date_unix():
    # Best-effort heuristic: filesystem creation time of root, or earliest
    # timestamp found on key system directories.
    candidates = ["/", "/etc", "/var/log/installer", "/lost+found"]
    earliest = None
    for path in candidates:
        try:
            st = os.stat(path)
            ts = getattr(st, "st_birthtime", None) or st.st_ctime
            if earliest is None or ts < earliest:
                earliest = ts
        except Exception:
            continue
    return human_time(earliest) if earliest else "Unavailable"


def print_system_info():
    header("SYSTEM INFORMATION")
    uname = platform.uname()
    print(c(f"OS:            {uname.system} {uname.release} ({uname.version})", Color.WHITE))
    print(c(f"Machine:       {uname.machine}", Color.WHITE))
    print(c(f"Node name:     {uname.node}", Color.WHITE))
    print(c(f"Processor:     {uname.processor or 'unknown'}", Color.WHITE))
    print(c(f"Python:        {platform.python_version()}", Color.WHITE))

    if platform.system() == "Windows":
        install_date = get_install_date_windows()
    else:
        install_date = get_install_date_unix()

    print(c(f"Install date:  {install_date}", Color.WHITE))


# ----------------------------- Section 2: Temp files -----------------------------

def get_temp_dirs():
    dirs = []
    if platform.system() == "Windows":
        local_temp = os.environ.get("TEMP") or os.environ.get("TMP")
        if local_temp:
            dirs.append(("User Temp", local_temp))
        windir = os.environ.get("WINDIR", r"C:\Windows")
        admin_temp = os.path.join(windir, "Temp")
        dirs.append(("Admin/System Temp", admin_temp))
        # Also check AppData Local Temp
        appdata = os.environ.get("LOCALAPPDATA", "")
        if appdata:
            dirs.append(("AppData Temp", os.path.join(appdata, "Temp")))
    else:
        dirs.append(("Temp", "/tmp"))
        dirs.append(("Var Tmp", "/var/tmp"))
    return dirs


def print_temp_summary():
    subheader("TEMPORARY / ADMIN TEMP FILES")
    total = 0
    for label, path in get_temp_dirs():
        count = 0
        for _ in safe_walk(path, max_depth=3):
            count += 1
        total += count
        print(c(f"{label} ({path}): {count} files", Color.WHITE))
    print(c(f"Total temp files found: {total}", Color.WHITE + Color.BOLD))


# ----------------------------- Section 3: Downloaded files -----------------------------

def get_downloads_dir():
    home = Path.home()
    candidates = [home / "Downloads"]
    # Additional common download locations
    if platform.system() == "Windows":
        candidates.append(Path(os.environ.get("USERPROFILE", "")) / "Downloads")
        candidates.append(Path(os.environ.get("USERPROFILE", "")) / "Desktop")
    return [p for p in candidates if p.exists()]


def print_downloads_summary():
    subheader("DOWNLOADED FILES")
    all_files = []
    for d in get_downloads_dir():
        for f in safe_walk(d, max_depth=4):
            if f.is_file():
                all_files.append(f)

    print(c(f"Downloads folder file count: {len(all_files)}", Color.WHITE))

    if not all_files:
        print(c("(No downloads folder found or it is empty)", Color.GRAY))
        return all_files

    all_files.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0, reverse=True)
    print(c(f"Most recent {min(MAX_LIST, len(all_files))} downloaded files:", Color.WHITE))
    for f in all_files[:MAX_LIST]:
        try:
            mtime = human_time(f.stat().st_mtime)
            size_kb = f.stat().st_size / 1024
            print(c(f"  [{mtime}] {f.name}  ({size_kb:.1f} KB)", Color.YELLOW))
        except Exception:
            continue

    return all_files


# ----------------------------- Section 4: Comprehensive Executable Scan -----------------------------

def scan_all_executables():
    """Scan all executable files across common system locations, similar to the image."""
    subheader("EXECUTABLE FILES TRACES")
    
    # Define scan locations
    scan_locations = []
    
    if platform.system() == "Windows":
        # Windows system locations
        windir = os.environ.get("WINDIR", r"C:\Windows")
        scan_locations.append(("System32", os.path.join(windir, "System32")))
        scan_locations.append(("SysWOW64", os.path.join(windir, "SysWOW64")))
        scan_locations.append(("Program Files", os.environ.get("ProgramFiles", r"C:\Program Files")))
        scan_locations.append(("Program Files (x86)", os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")))
        
        # User locations
        userprofile = os.environ.get("USERPROFILE", "")
        scan_locations.append(("User Profile", userprofile))
        scan_locations.append(("AppData Local", os.environ.get("LOCALAPPDATA", "")))
        scan_locations.append(("AppData Roaming", os.environ.get("APPDATA", "")))
        
        # Common locations for 3rd party apps
        scan_locations.append(("Downloads", os.path.join(userprofile, "Downloads")))
        scan_locations.append(("Desktop", os.path.join(userprofile, "Desktop")))
        scan_locations.append(("Documents", os.path.join(userprofile, "Documents")))
        
        # Additional common locations from the image
        scan_locations.append(("Temp", os.environ.get("TEMP", "")))
        scan_locations.append(("System Temp", os.path.join(windir, "Temp")))
        
        # Check other drives
        for drive in ["D:", "E:", "F:"]:
            if os.path.exists(drive):
                scan_locations.append((f"Drive {drive}", drive))
    else:
        # Unix/Linux locations
        scan_locations.append(("/usr/bin", "/usr/bin"))
        scan_locations.append(("/usr/sbin", "/usr/sbin"))
        scan_locations.append(("/usr/local/bin", "/usr/local/bin"))
        scan_locations.append(("/bin", "/bin"))
        scan_locations.append(("/sbin", "/sbin"))
        scan_locations.append(("/opt", "/opt"))
        scan_locations.append(("/home", "/home"))
        scan_locations.append(("/tmp", "/tmp"))
    
    all_executables = []
    all_flagged = []
    all_unsigned = []
    
    print(c("Scanning common locations for executable files...", Color.GRAY))
    print()
    
    # Scan each location
    for label, location in scan_locations:
        if not location or not os.path.exists(location):
            continue
            
        count = 0
        print(c(f"\n--- {label} ({location}) ---", Color.CYAN + Color.BOLD))
        
        try:
            for filepath in safe_walk(location, max_depth=4):
                if not filepath.is_file():
                    continue
                    
                ext = filepath.suffix.lower()
                if ext not in EXECUTABLE_EXTENSIONS:
                    continue
                    
                try:
                    size, mtime = get_file_info(filepath)
                    mtime_str = human_time(mtime)
                    size_mb = size / (1024 * 1024)
                    
                    # Get signature status if on Windows
                    sig_status = "Unknown"
                    if platform.system() == "Windows" and ext in {".exe", ".dll", ".msi"}:
                        sig_status = check_signature_windows(filepath)
                    
                    # Format output like the image
                    file_info = {
                        'path': str(filepath),
                        'mtime': mtime_str,
                        'size': size_mb,
                        'signature': sig_status,
                        'name': filepath.name,
                        'ext': ext
                    }
                    all_executables.append(file_info)
                    
                    # Check for suspicious patterns
                    flagged = False
                    reasons = []
                    
                    # Check if unsigned
                    if sig_status == "Not signed" and ext in {".exe", ".dll"}:
                        reasons.append("Not signed")
                        flagged = True
                    
                    # Check if in temp directories
                    path_lower = str(filepath).lower()
                    if "temp" in path_lower and ext in {".exe", ".scr", ".dll"}:
                        reasons.append("In temp directory")
                        flagged = True
                    
                    # Check if recently modified (last 14 days)
                    now = time.time()
                    if mtime >= (now - RECENT_DAYS * 86400):
                        reasons.append("Recently modified")
                        flagged = True
                    
                    # Check for double extensions
                    if filepath.name.lower().count(".") >= 2 and ext == ".exe":
                        stem_parts = filepath.name.lower().split(".")
                        if len(stem_parts) >= 3 and stem_parts[-2] in (
                            "pdf", "jpg", "png", "doc", "docx", "txt", "mp3", "mp4", "zip", "rar"
                        ):
                            reasons.append("Double extension")
                            flagged = True
                    
                    if flagged:
                        all_flagged.append((file_info, reasons))
                    
                    # Display the file in the format from the image
                    if flagged:
                        color = Color.RED
                        status_marker = "⚠"
                    elif sig_status == "Not signed":
                        color = Color.YELLOW
                        status_marker = "!"
                    else:
                        color = Color.WHITE
                        status_marker = " "
                    
                    # Build display line like: "2026-06-21 08:56:49    path\to\file.exe    Not signed"
                    display = f"  {mtime_str}    {filepath.name}    {sig_status}"
                    
                    if flagged:
                        print(c(f"  {display}    [{', '.join(reasons)}]", Color.RED))
                        count += 1
                    elif sig_status == "Not signed":
                        print(c(f"  {display}", Color.YELLOW))
                        count += 1
                    else:
                        print(c(f"  {display}", Color.WHITE))
                    
                    # Limit output to avoid overwhelming
                    if count >= 100:
                        print(c(f"  ... (showing first 100 files from this location)", Color.GRAY))
                        break
                        
                except Exception as e:
                    continue
                    
        except Exception as e:
            print(c(f"  Error scanning {location}: {e}", Color.RED))
    
    print()
    print(c("=" * 70, Color.CYAN))
    print(c(f"TOTAL EXECUTABLES FOUND: {len(all_executables)}", Color.WHITE + Color.BOLD))
    print(c(f"FLAGGED FOR REVIEW: {len(all_flagged)}", Color.RED + Color.BOLD))
    print(c("=" * 70, Color.CYAN))
    
    return all_executables, all_flagged


# ----------------------------- Section 5: Suspicious file heuristics -----------------------------

def scan_suspicious(downloaded_files):
    """Original heuristic scan function - kept for compatibility but merged into comprehensive scan"""
    # This is now part of scan_all_executables, but kept for backward compatibility
    return []


# ----------------------------- Main -----------------------------

def print_disclaimer():
    print(c(
        "NOTE: This tool scans executable files across common system locations.\n"
        "A flag does NOT confirm malware -- it only means the file matches a pattern\n"
        "worth your own review. Always verify manually before deleting anything.",
        Color.GRAY
    ))


def main():
    enable_windows_ansi()
    os.system("")  # also helps enable ANSI on some Windows terminals

    print(c("\n HIDAN SCRIPT PC CHECK\n", Color.CYAN + Color.BOLD))
    print_disclaimer()
    print()

    print_system_info()
    print_temp_summary()
    downloaded = print_downloads_summary()
    
    # Run the comprehensive executable scan
    executables, flagged = scan_all_executables()
    
    # Also run the heuristic scan for comparison
    # scan_suspicious(downloaded)

    header("SUMMARY")
    if flagged:
        print(c(f"{len(flagged)} file(s) flagged for review.", Color.RED + Color.BOLD))
        print(c("  - Check for unsigned executables", Color.YELLOW))
        print(c("  - Check for executables in temp directories", Color.YELLOW))
        print(c("  - Check for recently modified suspicious files", Color.YELLOW))
    else:
        print(c("No flags raised. System looks clean by these heuristics.", Color.YELLOW))
    print(c("\nScan complete.\n", Color.WHITE))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\nScan interrupted by user.", Color.YELLOW))
        sys.exit(1)
    except Exception as e:
        print(c(f"\nUnexpected error: {e}", Color.RED))
        sys.exit(1)
