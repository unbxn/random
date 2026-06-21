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
    By Hidan scripts v1.8
""")
print("=" * 70)

import os
import sys
import platform
import subprocess
import time
import datetime
import re
import glob
from pathlib import Path
from collections import defaultdict

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
    line = "=" * 60
    print(c(line, Color.CYAN))
    print(c(f" {title}", Color.CYAN + Color.BOLD))
    print(c(line, Color.CYAN))


def subheader(title):
    print()
    print(c(f"-- {title} --", Color.WHITE + Color.BOLD))


# ----------------------------- Helpers -----------------------------

SUSPICIOUS_EXTENSIONS = {".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs"}

RECENT_DAYS = 14
MAX_LIST = 250
MAX_DEPTH = 8

# ----------------------------- NEW: Prefetch Analysis -----------------------------

def get_prefetch_files_windows():
    """Retrieve and analyze Windows prefetch files for suspicious patterns."""
    prefetch_flags = []
    
    if platform.system() != "Windows":
        return prefetch_flags
    
    prefetch_paths = [
        r"C:\Windows\Prefetch",
        r"C:\Windows\System32\Prefetch"
    ]
    
    for prefetch_path in prefetch_paths:
        if not Path(prefetch_path).exists():
            continue
            
        try:
            for pf_file in Path(prefetch_path).glob("*.pf"):
                try:
                    # Get file info
                    st = pf_file.stat()
                    file_size = st.st_size / 1024  # KB
                    mtime = st.st_mtime
                    
                    # Parse filename for application info
                    app_name = pf_file.stem
                    
                    # Look for suspicious indicators
                    flags = []
                    
                    # Check for suspicious application names
                    suspicious_apps = [
                        "cheat", "hack", "injector", "wallhack", "aimbot", 
                        "triggerbot", "esp", "radar", "overlay", "mod", 
                        "bypass", "crack", "keygen", "loader", "inject",
                        "memory", "dump", "spoof", "fake", "steam", "epic",
                        "easyanticheat", "battleye", "gameguard", "punkbuster"
                    ]
                    
                    for susp in suspicious_apps:
                        if susp in app_name.lower():
                            flags.append(f"Contains keyword '{susp}'")
                            break
                    
                    # Check for unusually large prefetch files
                    if file_size > 100:  # Normal prefetch files are usually < 100KB
                        flags.append(f"Large file size: {file_size:.1f} KB")
                    
                    # Check for recent modification
                    recent_time = time.time() - (RECENT_DAYS * 86400)
                    if mtime >= recent_time:
                        flags.append(f"Modified within last {RECENT_DAYS} days")
                    
                    # Check for applications in unusual locations (from prefetch traces)
                    if "temp" in app_name.lower() or "download" in app_name.lower():
                        flags.append("Application appears to be from temp/download location")
                    
                    if flags:
                        prefetch_flags.append({
                            'file': pf_file,
                            'name': app_name,
                            'size': file_size,
                            'mtime': mtime,
                            'flags': flags
                        })
                        
                except Exception as e:
                    # Skip individual files that cause errors
                    continue
                    
        except Exception as e:
            # Skip entire prefetch directory if error
            continue
    
    return prefetch_flags


def analyze_prefetch_details():
    """Enhanced prefetch analysis with detailed information."""
    subheader("PREFETCH ANALYSIS")
    
    if platform.system() != "Windows":
        print(c("Prefetch analysis is only available on Windows systems.", Color.GRAY))
        return [], []
    
    print(c("Scanning Windows Prefetch directory for suspicious traces...", Color.CYAN))
    
    prefetch_flags = get_prefetch_files_windows()
    
    if not prefetch_flags:
        print(c("No suspicious prefetch entries found.", Color.GREEN))
        return [], []
    
    print(c(f"\nFound {len(prefetch_flags)} suspicious prefetch entries:", Color.RED + Color.BOLD))
    
    # Sort by recent modification
    prefetch_flags.sort(key=lambda x: x['mtime'], reverse=True)
    
    for idx, entry in enumerate(prefetch_flags, 1):
        print()
        print(c(f"[{idx}/{len(prefetch_flags)}] {c('PREFETCH FLAG', Color.RED)}", Color.WHITE + Color.BOLD))
        print(c(f"  Application: {entry['name']}", Color.WHITE))
        print(c(f"  Path: {entry['file']}", Color.GRAY))
        print(c(f"  Size: {entry['size']:.1f} KB", Color.YELLOW))
        print(c(f"  Modified: {human_time(entry['mtime'])}", Color.YELLOW))
        
        for flag in entry['flags']:
            print(c(f"  ⚠️  {flag}", Color.RED))
    
    return prefetch_flags, [entry['name'] for entry in prefetch_flags]


# ----------------------------- NEW: Event Viewer Logs (IDs 1000 and 1001) -----------------------------

def get_event_logs_windows():
    """Query Windows Event Logs for application errors (IDs 1000 and 1001)."""
    event_logs = []
    
    if platform.system() != "Windows":
        return event_logs
    
    try:
        # Query for Event ID 1000 and 1001 from Application log
        # Using wevtutil for reliable event log queries
        query_cmd = [
            "wevtutil", "qe", "Application",
            "/q:*[System[EventID=1000 or EventID=1001]]",
            "/c:100", "/f:text", "/rd:true"  # Increased to 100 events
        ]
        
        result = subprocess.run(
            query_cmd,
            capture_output=True,
            text=True,
            timeout=30
        )
        
        if result.returncode != 0:
            print(c("  Warning: Could not query event logs with wevtutil.", Color.YELLOW))
            # Try alternative method using PowerShell
            ps_cmd = [
                "powershell", "-Command",
                "Get-WinEvent -LogName Application -FilterXPath \"*[System[EventID=1000 or EventID=1001]]\" -MaxEvents 100 | Select-Object TimeCreated, Message"
            ]
            
            result = subprocess.run(
                ps_cmd,
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0 and result.stdout:
                event_logs = parse_event_logs_ps(result.stdout)
        
        else:
            event_logs = parse_event_logs_windows(result.stdout)
            
    except Exception as e:
        print(c(f"  Error querying event logs: {str(e)}", Color.RED))
    
    return event_logs


def parse_event_logs_windows(text):
    """Parse wevtutil output for event log details."""
    events = []
    current_event = {}
    
    lines = text.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Detect event boundaries (Event[0], Event[1], etc.)
        if line.startswith('Event['):
            if current_event:
                events.append(current_event)
                current_event = {}
            continue
        
        # Extract important fields
        if 'EventID' in line or 'Event ID' in line:
            match = re.search(r'EventID?\s*:\s*(\d+)', line, re.IGNORECASE)
            if match:
                current_event['event_id'] = match.group(1)
        
        if 'TimeCreated' in line:
            match = re.search(r'TimeCreated\s*:\s*(.+?)(?:\s*\[|$)', line)
            if match:
                current_event['time'] = match.group(1).strip()
        
        # Extract faulting application details
        if 'Faulting application name' in line:
            match = re.search(r'Faulting application name\s*:\s*(.+?)(?:\r|\n|$)', line, re.IGNORECASE)
            if match:
                current_event['app_name'] = match.group(1).strip()
        
        if 'Faulting application path' in line:
            match = re.search(r'Faulting application path\s*:\s*(.+?)(?:\r|\n|$)', line, re.IGNORECASE)
            if match:
                current_event['app_path'] = match.group(1).strip()
        
        if 'Faulting module name' in line:
            match = re.search(r'Faulting module name\s*:\s*(.+?)(?:\r|\n|$)', line, re.IGNORECASE)
            if match:
                current_event['module'] = match.group(1).strip()
        
        if 'Exception code' in line:
            match = re.search(r'Exception code\s*:\s*(.+?)(?:\r|\n|$)', line, re.IGNORECASE)
            if match:
                current_event['exception'] = match.group(1).strip()
    
    if current_event:
        events.append(current_event)
    
    return events


def parse_event_logs_ps(text):
    """Parse PowerShell output for event log details."""
    events = []
    current_event = {}
    
    lines = text.split('\n')
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        
        if 'TimeCreated' in line:
            # Extract time
            match = re.search(r'TimeCreated\s*:\s*(.+?)$', line)
            if match:
                current_event['time'] = match.group(1).strip()
        
        if 'Message' in line:
            message = line.replace('Message :', '').strip()
            if not message or message.startswith('--------'):
                continue
                
            # Parse message for details - look for specific fields
            app_match = re.search(r'Faulting application name:\s*(.+?)(?:\r|\n|$)', message, re.IGNORECASE)
            if app_match:
                current_event['app_name'] = app_match.group(1).strip()
            
            app_path_match = re.search(r'Faulting application path:\s*(.+?)(?:\r|\n|$)', message, re.IGNORECASE)
            if app_path_match:
                current_event['app_path'] = app_path_match.group(1).strip()
            
            module_match = re.search(r'Faulting module name:\s*(.+?)(?:\r|\n|$)', message, re.IGNORECASE)
            if module_match:
                current_event['module'] = module_match.group(1).strip()
            
            exception_match = re.search(r'Exception code:\s*(.+?)(?:\r|\n|$)', message, re.IGNORECASE)
            if exception_match:
                current_event['exception'] = exception_match.group(1).strip()
            
            # Extract event ID from message or set default
            event_id_match = re.search(r'Event ID:\s*(\d+)', message, re.IGNORECASE)
            if event_id_match:
                current_event['event_id'] = event_id_match.group(1)
            else:
                # Determine from message content
                if '1000' in message or 'appcrash' in message.lower():
                    current_event['event_id'] = '1000'
                elif '1001' in message or 'apphang' in message.lower():
                    current_event['event_id'] = '1001'
            
            current_event['message'] = message
            
            # If we have an event with details, add it and reset
            if current_event:
                events.append(current_event)
                current_event = {}
    
    return events


def print_event_logs(events):
    """Display event log findings."""
    subheader("EVENT VIEWER LOGS (IDs 1000 and 1001)")
    
    if platform.system() != "Windows":
        print(c("Event Viewer analysis is only available on Windows systems.", Color.GRAY))
        return [], []
    
    print(c("Querying Application Event Log for Event IDs 1000 and 1001...", Color.CYAN))
    
    events = get_event_logs_windows()
    
    if not events:
        print(c("No Event ID 1000 or 1001 events found in the last 100 records.", Color.GREEN))
        return [], []
    
    # Display ALL events with their full details
    print(c(f"\nFound {len(events)} events with Event IDs 1000 or 1001:", Color.CYAN + Color.BOLD))
    
    for idx, event in enumerate(events, 1):
        print()
        print(c(f"[{idx}/{len(events)}] {c('EVENT LOG', Color.YELLOW)}", Color.WHITE + Color.BOLD))
        
        if 'time' in event:
            print(c(f"  Time: {event['time']}", Color.YELLOW))
        if 'event_id' in event:
            print(c(f"  Event ID: {event['event_id']}", Color.YELLOW))
        if 'app_name' in event:
            print(c(f"  Faulting application name: {event['app_name']}", Color.WHITE))
        if 'app_path' in event:
            print(c(f"  Faulting application path: {event['app_path']}", Color.GRAY))
        if 'module' in event:
            print(c(f"  Faulting module: {event['module']}", Color.GRAY))
        if 'exception' in event:
            print(c(f"  Exception code: {event['exception']}", Color.RED))
        
        # Check for suspicious applications
        suspicious_keywords = [
            'cheat', 'hack', 'inject', 'mod', 'crack', 'keygen', 'loader', 'bot',
            'macro', 'script', 'exploit', 'trainer', 'overlay', 'radar', 'esp',
            'aimbot', 'triggerbot', 'wallhack', 'bypass', 'memory', 'spoof'
        ]
        
        if 'app_name' in event:
            app_name_lower = event['app_name'].lower()
            matched = [kw for kw in suspicious_keywords if kw in app_name_lower]
            if matched:
                print(c(f"  ⚠️  Suspicious keywords found: {', '.join(matched)}", Color.RED))
    
    # Filter for suspicious applications for return
    suspicious_events = []
    suspicious_keywords = [
        'cheat', 'hack', 'inject', 'mod', 'crack', 'keygen', 'loader', 'bot',
        'macro', 'script', 'exploit', 'trainer', 'overlay', 'radar', 'esp',
        'aimbot', 'triggerbot', 'wallhack', 'bypass', 'memory', 'spoof'
    ]
    
    for event in events:
        event_text = str(event).lower()
        is_suspicious = False
        matched_keywords = []
        
        for keyword in suspicious_keywords:
            if keyword in event_text:
                is_suspicious = True
                matched_keywords.append(keyword)
        
        if is_suspicious:
            suspicious_events.append((event, matched_keywords))
    
    if suspicious_events:
        print(c(f"\nFound {len(suspicious_events)} suspicious events:", Color.RED + Color.BOLD))
    
    return suspicious_events, [event.get('app_name', '') for event, _ in suspicious_events]


# ----------------------------- NEW: Deleted File Traces -----------------------------

def scan_deleted_file_traces():
    """Scan for traces of deleted files through various methods."""
    subheader("DELETED FILE TRACES")
    
    traces_found = []
    trace_details = defaultdict(list)
    
    # Method 1: Check Recycle Bin / Trash
    print(c("Checking Recycle Bin/Trash for recently deleted items...", Color.CYAN))
    
    if platform.system() == "Windows":
        recycle_patterns = [
            r"C:\$Recycle.bin\*",
            r"C:\System Volume Information\*",
            r"%SystemRoot%\Prefetch\*"  # Some deleted files leave prefetch traces
        ]
        
        for pattern in recycle_patterns:
            try:
                expanded = os.path.expandvars(pattern)
                matches = glob.glob(expanded, recursive=True)
                
                for path_str in matches[:20]:  # Limit to avoid too much output
                    path = Path(path_str)
                    if path.is_file():
                        try:
                            st = path.stat()
                            if time.time() - st.st_mtime <= (RECENT_DAYS * 86400):
                                trace_details['Recycle Bin'].append({
                                    'path': str(path),
                                    'mtime': st.st_mtime,
                                    'size': st.st_size
                                })
                        except:
                            pass
            except:
                continue
    
    else:  # Linux/Mac
        trash_paths = [
            Path.home() / ".local/share/Trash",
            Path.home() / ".trash",
            "/tmp"
        ]
        
        for trash in trash_paths:
            if trash.exists():
                for file_pattern in ["*", "*/"]:
                    for item in trash.glob(f"**/{file_pattern}"):
                        try:
                            if item.is_file() and item.name != ".trashinfo":
                                st = item.stat()
                                if time.time() - st.st_mtime <= (RECENT_DAYS * 86400):
                                    trace_details['Trash'].append({
                                        'path': str(item),
                                        'mtime': st.st_mtime,
                                        'size': st.st_size
                                    })
                        except:
                            continue
    
    # Method 2: Check for common trace files
    trace_patterns = []
    if platform.system() == "Windows":
        trace_patterns = [
            "%TEMP%\\*.tmp",
            "%TEMP%\\*.log",
            "C:\\Windows\\Temp\\*",
            "%APPDATA%\\*\\*.tmp"
        ]
    else:
        trace_patterns = [
            "/tmp/*.tmp",
            "/var/tmp/*.tmp",
            "/var/log/*.tmp"
        ]
    
    print(c("Checking for temporary file traces...", Color.CYAN))
    
    for pattern in trace_patterns:
        try:
            expanded = os.path.expandvars(pattern)
            matches = glob.glob(expanded, recursive=False)
            
            for path_str in matches[:20]:
                path = Path(path_str)
                if path.is_file():
                    try:
                        st = path.stat()
                        if time.time() - st.st_mtime <= (RECENT_DAYS * 86400):
                            trace_details['Temporary Files'].append({
                                'path': str(path),
                                'mtime': st.st_mtime,
                                'size': st.st_size
                            })
                    except:
                        pass
        except:
            continue
    
    # Display results
    total_traces = sum(len(items) for items in trace_details.values())
    
    if total_traces == 0:
        print(c("No traces of recently deleted or temporary files found.", Color.GREEN))
        return []
    
    print(c(f"\nFound {total_traces} file traces in recent {RECENT_DAYS} days:", Color.YELLOW))
    
    for category, items in trace_details.items():
        if items:
            print()
            print(c(f"  [{category}] {len(items)} items:", Color.CYAN + Color.BOLD))
            
            for item in items[:10]:  # Show first 10 per category
                size_kb = item.get('size', 0) / 1024
                mtime_str = human_time(item.get('mtime', 0))
                path_str = item.get('path', 'unknown')
                
                print(c(f"    - {path_str}", Color.WHITE))
                print(c(f"      Modified: {mtime_str}  Size: {size_kb:.1f} KB", Color.GRAY))
            
            if len(items) > 10:
                print(c(f"    ... and {len(items) - 10} more", Color.GRAY))
    
    return traces_found


# ----------------------------- Modified Functions -----------------------------

def human_time(ts):
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "unknown"


def safe_walk(root, max_depth=8):
    """Walk a directory tree with a depth limit, skipping errors silently."""
    root = Path(root)
    if not root.exists():
        return
    root_depth = len(root.parts)
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda e: None):
        depth = len(Path(dirpath).parts) - root_depth
        if depth >= max_depth:
            dirnames[:] = []
        for fname in filenames:
            yield Path(dirpath) / fname


def get_all_drives():
    """Get all available drives/partitions for thorough scanning."""
    drives = []
    
    if platform.system() == "Windows":
        for drive_letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive_path = f"{drive_letter}:\\"
            if os.path.exists(drive_path):
                try:
                    import ctypes
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                    if drive_type in (2, 3):
                        drives.append(Path(drive_path))
                except:
                    drives.append(Path(drive_path))
    else:
        try:
            import psutil
            for partition in psutil.disk_partitions():
                if partition.fstype and 'tmpfs' not in partition.fstype and 'devtmpfs' not in partition.fstype:
                    try:
                        p = Path(partition.mountpoint)
                        if p.exists():
                            drives.append(p)
                    except:
                        pass
        except:
            common_mounts = ["/", "/home", "/mnt", "/media"]
            for mount in common_mounts:
                p = Path(mount)
                if p.exists():
                    drives.append(p)
    
    return drives, []


def is_system_directory(path):
    """Check if path is a critical system directory to avoid scanning."""
    path_str = str(path).lower()
    system_paths = [
        "windows/system32", "windows/system", "windows/assembly",
        "program files", "program files (x86)", "windows/winsxs",
        "/sys/", "/proc/", "/dev/", "/run/", "/snap/",
        "/lib/", "/lib64/", "/usr/lib/", "/usr/lib64/"
    ]
    
    for sys_path in system_paths:
        if sys_path in path_str:
            return True
    return False


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
    
    drives, _ = get_all_drives()
    print(c(f"Drives to scan: {', '.join([str(d) for d in drives])}", Color.GREEN))


def get_temp_dirs():
    dirs = []
    if platform.system() == "Windows":
        local_temp = os.environ.get("TEMP") or os.environ.get("TMP")
        if local_temp:
            dirs.append(("User Temp", local_temp))
        windir = os.environ.get("WINDIR", r"C:\Windows")
        admin_temp = os.path.join(windir, "Temp")
        dirs.append(("Admin/System Temp", admin_temp))
    else:
        dirs.append(("Temp", "/tmp"))
        dirs.append(("Var Tmp", "/var/tmp"))
    return dirs


def print_temp_summary():
    subheader("TEMPORARY / ADMIN TEMP FILES")
    
    for label, path in get_temp_dirs():
        flagged_files = []
        total_count = 0
        
        print(c(f"\nScanning {label} ({path}):", Color.CYAN))
        
        for f in safe_walk(path, max_depth=3):
            if not f.is_file():
                continue
            total_count += 1
            
            # Check for flags
            reasons = []
            ext = f.suffix.lower()
            path_str = str(f).lower()
            
            # Check for executable/script files
            if ext in (".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs"):
                # Check for suspicious patterns
                if "temp" in path_str or "tmp" in path_str:
                    reasons.append("Executable/script in temp location")
                
                # Check for recent modification
                try:
                    st = f.stat()
                    recent_time = time.time() - (RECENT_DAYS * 86400)
                    if st.st_mtime >= recent_time:
                        reasons.append(f"Modified within last {RECENT_DAYS} days")
                except:
                    pass
                
                # Check for double extensions
                if f.name.lower().count(".") >= 2 and ext == ".exe":
                    stem_parts = f.name.lower().split(".")
                    if len(stem_parts) >= 3 and stem_parts[-2] in (
                        "pdf", "jpg", "png", "doc", "docx", "txt", "mp3", "mp4",
                        "zip", "rar", "7z", "avi", "mkv", "mpg", "mpeg"
                    ):
                        reasons.append("Double file extension (disguise pattern)")
                
                # Check for common suspicious names
                suspicious_names = ["cheat", "hack", "inject", "mod", "crack", "keygen", "loader"]
                if any(name in f.name.lower() for name in suspicious_names):
                    reasons.append(f"Suspicious filename pattern")
                
                if reasons:
                    flagged_files.append((f, reasons))
        
        if flagged_files:
            print(c(f"  Found {len(flagged_files)} suspicious files in {label}:", Color.RED + Color.BOLD))
            for f, reasons in flagged_files[:10]:
                print(c(f"    ⚠️  {f.name}", Color.RED))
                try:
                    st = f.stat()
                    print(c(f"       Path: {f}", Color.GRAY))
                    print(c(f"       Modified: {human_time(st.st_mtime)}  Size: {st.st_size/1024:.1f} KB", Color.YELLOW))
                except:
                    pass
                for reason in reasons:
                    print(c(f"       {reason}", Color.RED))
            
            if len(flagged_files) > 10:
                print(c(f"    ... and {len(flagged_files) - 10} more flagged files", Color.GRAY))
        else:
            print(c(f"  No suspicious files found in {label}", Color.GREEN))


def get_downloads_dir():
    home = Path.home()
    candidates = [home / "Downloads"]
    if platform.system() == "Windows":
        candidates.append(home / "Documents" / "Downloads")
        candidates.append(home / "Desktop")
    return [p for p in candidates if p.exists()]


def print_downloads_summary():
    subheader("DOWNLOADED FILES")
    all_files = []
    flagged_files = []
    zip_files = []
    
    for d in get_downloads_dir():
        for f in safe_walk(d, max_depth=4):
            if f.is_file():
                all_files.append(f)
                
                ext = f.suffix.lower()
                path_str = str(f).lower()
                
                # Collect all ZIP files
                if ext == ".zip":
                    zip_files.append(f)
                
                # Check for executable files with flags
                if ext in (".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs"):
                    reasons = []
                    
                    # Check for suspicious patterns
                    suspicious_names = ["cheat", "hack", "inject", "mod", "crack", "keygen", "loader", "bot"]
                    if any(name in f.name.lower() for name in suspicious_names):
                        reasons.append(f"Suspicious filename pattern")
                    
                    # Check for double extensions
                    if f.name.lower().count(".") >= 2 and ext == ".exe":
                        stem_parts = f.name.lower().split(".")
                        if len(stem_parts) >= 3 and stem_parts[-2] in (
                            "pdf", "jpg", "png", "doc", "docx", "txt", "mp3", "mp4",
                            "zip", "rar", "7z", "avi", "mkv", "mpg", "mpeg"
                        ):
                            reasons.append("Double file extension (disguise pattern)")
                    
                    # Check for recent modification
                    try:
                        st = f.stat()
                        recent_time = time.time() - (RECENT_DAYS * 86400)
                        if st.st_mtime >= recent_time:
                            reasons.append(f"Modified within last {RECENT_DAYS} days")
                    except:
                        pass
                    
                    if reasons:
                        flagged_files.append((f, reasons))

    print(c(f"\nDownloads folder total file count: {len(all_files)}", Color.WHITE))
    
    # Display ZIP files
    if zip_files:
        print(c(f"\nZIP files found ({len(zip_files)}):", Color.CYAN + Color.BOLD))
        for f in zip_files[:20]:
            try:
                st = f.stat()
                print(c(f"  📦 {f.name} ({st.st_size/1024:.1f} KB)", Color.WHITE))
                print(c(f"     Modified: {human_time(st.st_mtime)}", Color.GRAY))
            except:
                print(c(f"  📦 {f.name}", Color.WHITE))
        if len(zip_files) > 20:
            print(c(f"  ... and {len(zip_files) - 20} more ZIP files", Color.GRAY))
    else:
        print(c("No ZIP files found in downloads.", Color.GREEN))
    
    # Display flagged executable files
    if flagged_files:
        print(c(f"\n⚠️  Flagged executable/script files found ({len(flagged_files)}):", Color.RED + Color.BOLD))
        for f, reasons in flagged_files[:20]:
            print(c(f"  ⚠️  {f.name}", Color.RED))
            try:
                st = f.stat()
                print(c(f"     Path: {f}", Color.GRAY))
                print(c(f"     Modified: {human_time(st.st_mtime)}  Size: {st.st_size/1024:.1f} KB", Color.YELLOW))
            except:
                pass
            for reason in reasons:
                print(c(f"     {reason}", Color.RED))
        if len(flagged_files) > 20:
            print(c(f"  ... and {len(flagged_files) - 20} more flagged files", Color.GRAY))
    else:
        print(c("No suspicious executable files found in downloads.", Color.GREEN))
    
    return all_files


def scan_suspicious_full(downloaded_files):
    subheader("FULL SYSTEM SUSPICIOUS FILE SCAN")
    print(c("Scanning all drives thoroughly... This may take a while.", Color.YELLOW))
    print("")
    print(c("NOTE: Skipping critical system directories for performance.", Color.GRAY))
    print()
    
    flags = []
    notices = []
    scanned_count = 0
    
    drives, exclude_dirs = get_all_drives()
    now = time.time()
    recent_cutoff = now - (RECENT_DAYS * 86400)
    
    seen = set()
    
    for drive in drives:
        print(c(f"\nScanning drive: {drive}", Color.BLUE))
        drive_str = str(drive).lower()
        
        if platform.system() == "Windows":
            if "windows" in drive_str or "system32" in drive_str or "program files" in drive_str:
                print(c(f"  Skipping system directories on {drive}", Color.GRAY))
                continue
        
        try:
            for f in safe_walk(drive, max_depth=MAX_DEPTH):
                if not f.is_file():
                    continue
                    
                if is_system_directory(f):
                    continue
                    
                try:
                    key = str(f.resolve()) if f.exists() else str(f)
                    if key in seen:
                        continue
                    seen.add(key)
                except:
                    continue
                
                ext = f.suffix.lower()
                if ext not in SUSPICIOUS_EXTENSIONS:
                    continue
                
                try:
                    st = f.stat()
                    if st.st_size < 1024:
                        continue
                except Exception:
                    continue
                
                scanned_count += 1
                if scanned_count % 1000 == 0:
                    print(c(f"  Scanned {scanned_count} suspicious files...", Color.GRAY))
                
                reasons = []
                path_str = str(f).lower()
                
                if "temp" in path_str and ext in (".exe", ".scr"):
                    reasons.append("Executable located in a temp directory")
                
                is_hidden = f.name.startswith(".")
                if platform.system() == "Windows":
                    try:
                        import ctypes
                        attrs = ctypes.windll.kernel32.GetFileAttributesW(str(f))
                        FILE_ATTRIBUTE_HIDDEN = 0x2
                        if attrs != -1 and attrs & FILE_ATTRIBUTE_HIDDEN:
                            is_hidden = True
                    except Exception:
                        pass
                if is_hidden:
                    reasons.append("File is hidden")
                
                recently_modified = st.st_mtime >= recent_cutoff
                if recently_modified and ext in (".exe", ".scr"):
                    reasons.append(f"Executable modified within last {RECENT_DAYS} days")
                
                if f.name.lower().count(".") >= 2 and ext == ".exe":
                    stem_parts = f.name.lower().split(".")
                    if len(stem_parts) >= 3 and stem_parts[-2] in (
                        "pdf", "jpg", "png", "doc", "docx", "txt", "mp3", "mp4",
                        "zip", "rar", "7z", "avi", "mkv", "mpg", "mpeg"
                    ):
                        reasons.append("Double file extension (disguise pattern)")
                
                if ext in (".bat", ".vbs", ".ps1", ".cmd"):
                    if "temp" in path_str:
                        reasons.append("Script file in temp directory")
                    if "startup" in path_str:
                        reasons.append("Script in startup folder")
                    if "downloads" in path_str:
                        reasons.append("Script in downloads folder")
                
                if platform.system() == "Windows":
                    user_paths = ["users", "user", "documents", "desktop"]
                    if any(p in path_str for p in user_paths) and recently_modified:
                        reasons.append(f"Recently modified in user directory")
                
                if reasons:
                    flags.append((f, reasons, st.st_mtime, st.st_size))
                elif ext in (".exe", ".scr"):
                    notices.append(f)
                    
        except Exception as e:
            print(c(f"  Error scanning {drive}: {str(e)[:100]}", Color.GRAY))
            continue
    
    print(c(f"\nTotal suspicious files scanned: {scanned_count}", Color.CYAN))
    
    if not flags:
        print(c("\nNo suspicious indicators found based on current heuristics.", Color.YELLOW))
    else:
        flags.sort(key=lambda x: x[2], reverse=True)
        
        print(c(f"\n{'='*70}", Color.RED))
        print(c(f"FOUND {len(flags)} FLAGGED FILES:", Color.RED + Color.BOLD))
        print(c(f"{'='*70}", Color.RED))
        print()
        
        for idx, (f, reasons, mtime, size) in enumerate(flags, 1):
            print(c(f"[{idx}/{len(flags)}] {c('FLAGGED', Color.RED)} {f}", Color.WHITE + Color.BOLD))
            print(c(f"          Modified: {human_time(mtime)}  Size: {size/1024:.1f} KB", Color.YELLOW))
            for r in reasons:
                print(c(f"          ⚠️  {r}", Color.RED))
            print()

    print()
    print(c(f"Executable/script files scanned without flags: {len(notices)}", Color.YELLOW))
    if notices and len(notices) > 0:
        print(c("Sample (up to 10):", Color.YELLOW))
        for f in notices[:10]:
            print(c(f"  {f.name}", Color.YELLOW))

    return flags


# ----------------------------- Main -----------------------------

def print_disclaimer():
    print(c(
        "NOTE: This tool uses generic heuristics (location, hidden attribute,\n"
        "recent modification, double extensions). A flag does NOT confirm malware\n"
        "or cheat software -- it only means the file matches a pattern worth your\n"
        "own review. Always verify manually before deleting anything.\n"
        "This version includes enhanced Prefetch, Event Log, and deleted file trace analysis.",
        Color.GRAY
    ))


def main():
    enable_windows_ansi()
    os.system("")

    print(c("\n HIDAN SCRIPT FULL SYSTEM SCANNER v1.8\n", Color.CYAN + Color.BOLD))
    print_disclaimer()
    print()

    print_system_info()
    print_temp_summary()
    downloaded = print_downloads_summary()
    
    # NEW: Prefetch analysis
    prefetch_entries, prefetch_apps = analyze_prefetch_details()
    
    # NEW: Event Viewer logs
    suspicious_events, event_apps = print_event_logs([])
    
    # NEW: Deleted file traces
    deleted_traces = scan_deleted_file_traces()
    
    # Original file scan
    flags = scan_suspicious_full(downloaded)
    
    # Combined summary
    header("FULL SCAN SUMMARY")
    print("")
    
    total_flags = len(flags) + len(prefetch_entries) + len(suspicious_events)
    
    if total_flags > 0:
        print(c(f"TOTAL FLAGS FOUND: {total_flags}", Color.RED + Color.BOLD))
        print(c(f"  - File scan flags: {len(flags)}", Color.YELLOW))
        print(c(f"  - Prefetch flags: {len(prefetch_entries)}", Color.YELLOW))
        print(c(f"  - Event log flags: {len(suspicious_events)}", Color.YELLOW))
        print(c(f"  - Deleted file traces: {len(deleted_traces)}", Color.YELLOW))
    else:
        print(c("No flags raised. System looks clean by these heuristics.", Color.GREEN))
    
    print(c("\nFull system scan complete.\n", Color.WHITE))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\nScan interrupted by user.", Color.YELLOW))
        sys.exit(1)
    except Exception as e:
        print(c(f"\nUnexpected error: {e}", Color.RED))
        sys.exit(1)
