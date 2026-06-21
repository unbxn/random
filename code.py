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
    By Hidan scripts v1.7 - Enhanced Forensic Edition
""")
print("=" * 70)

import os
import sys
import platform
import subprocess
import time
import datetime
from pathlib import Path
import re
import glob

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


def get_windows_drive():
    """Get the Windows system drive."""
    if platform.system() == "Windows":
        windir = os.environ.get("WINDIR", "C:\\Windows")
        return windir[:3]  # Returns "C:\\" or similar
    return None


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
    if platform.system() == "Windows":
        candidates.append(home / "Documents" / "Downloads")
        candidates.append(home / "Desktop")
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


# ----------------------------- Section 4: PREFETCH ANALYSIS -----------------------------

def scan_prefetch():
    """Scan Windows Prefetch files for suspicious executables."""
    subheader("PREFETCH FILE ANALYSIS")
    
    if platform.system() != "Windows":
        print(c("Prefetch analysis is Windows-specific. Skipping.", Color.GRAY))
        return []
    
    prefetch_dirs = []
    windir = os.environ.get("WINDIR", "C:\\Windows")
    
    # Windows 10/11 prefetch location
    prefetch_path = os.path.join(windir, "Prefetch")
    if os.path.exists(prefetch_path):
        prefetch_dirs.append(prefetch_path)
    
    # Also check for older Windows versions
    prefetch_path_alt = os.path.join(windir, "system32", "Prefetch")
    if os.path.exists(prefetch_path_alt):
        prefetch_dirs.append(prefetch_path_alt)
    
    if not prefetch_dirs:
        print(c("No Prefetch directory found.", Color.GRAY))
        return []
    
    print(c(f"Scanning Prefetch directories: {', '.join(prefetch_dirs)}", Color.WHITE))
    
    suspicious_prefetch = []
    recent_cutoff = time.time() - (RECENT_DAYS * 86400)
    
    for prefetch_dir in prefetch_dirs:
        try:
            for pf_file in Path(prefetch_dir).glob("*.pf"):
                try:
                    st = pf_file.stat()
                    mod_time = st.st_mtime
                    
                    # Check if prefetch file is recent
                    if mod_time >= recent_cutoff:
                        # Extract executable name from prefetch filename
                        # Format: EXECUTABLE.EXE-XXXXXXXX.pf
                        pf_name = pf_file.name
                        exe_name = pf_name.split("-")[0] if "-" in pf_name else pf_name.replace(".pf", "")
                        
                        # Check for suspicious patterns
                        reasons = []
                        
                        # Check if it's a suspicious extension
                        ext = Path(exe_name).suffix.lower()
                        if ext in SUSPICIOUS_EXTENSIONS:
                            reasons.append(f"Suspicious extension: {ext}")
                        
                        # Check for common malware names or patterns
                        suspicious_keywords = [
                            'virus', 'malware', 'trojan', 'hack', 'keylog', 
                            'spy', 'ransom', 'crypt', 'miner', 'rootkit',
                            'inject', 'exploit', 'payload', 'worm'
                        ]
                        exe_lower = exe_name.lower()
                        for keyword in suspicious_keywords:
                            if keyword in exe_lower:
                                reasons.append(f"Suspicious keyword in filename: '{keyword}'")
                                break
                        
                        # Check for random-looking filenames (alphanumeric, no clear purpose)
                        if re.match(r'^[a-zA-Z0-9]{8,}\.(exe|scr|bat|cmd)$', exe_name):
                            reasons.append("Random-looking filename pattern")
                        
                        if reasons:
                            suspicious_prefetch.append((pf_file, exe_name, mod_time, reasons))
                            print(c(f"  ⚠️  FLAGGED: {pf_file.name} ({exe_name})", Color.RED))
                            for reason in reasons:
                                print(c(f"      -> {reason}", Color.YELLOW))
                        else:
                            # Still track but don't flag
                            print(c(f"  ✅ {pf_file.name} ({exe_name})", Color.GREEN))
                            
                except Exception as e:
                    print(c(f"  Error processing {pf_file}: {str(e)[:50]}", Color.GRAY))
                    continue
                    
        except Exception as e:
            print(c(f"Error scanning prefetch directory: {str(e)[:50]}", Color.GRAY))
            continue
    
    print(c(f"\nPrefetch analysis complete. Found {len(suspicious_prefetch)} flagged files.", 
            Color.CYAN if not suspicious_prefetch else Color.RED))
    return suspicious_prefetch


# ----------------------------- Section 5: EVENT VIEWER LOGS (Windows) -----------------------------

def scan_event_logs():
    """Scan Windows Event Logs for events 1000 and 1001 (application crashes/errors)."""
    subheader("EVENT VIEWER LOG ANALYSIS")
    
    if platform.system() != "Windows":
        print(c("Event log analysis is Windows-specific. Skipping.", Color.GRAY))
        return []
    
    print(c("Scanning Windows Event Logs for events 1000 and 1001 (application crashes)...", Color.WHITE))
    print(c("NOTE: This may take a moment.", Color.GRAY))
    
    suspicious_events = []
    recent_cutoff = datetime.datetime.now() - datetime.timedelta(days=RECENT_DAYS)
    recent_cutoff_str = recent_cutoff.strftime("%Y-%m-%d %H:%M:%S")
    
    try:
        # Query Application log for events 1000 and 1001
        for event_id in ["1000", "1001"]:
            cmd = [
                "wevtutil", "qe", "Application", 
                "/q:", f"*[System[(EventID={event_id})]]", 
                "/rd:true", "/c:20", "/f:text"
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30
            )
            
            if result.returncode != 0:
                print(c(f"  Could not query event ID {event_id}: {result.stderr[:100]}", Color.GRAY))
                continue
            
            # Parse the output
            current_event = {}
            lines = result.stdout.splitlines()
            
            for i, line in enumerate(lines):
                if "Event[0]" in line or "Event[" in line:
                    if current_event:
                        # Process previous event
                        process_event(current_event, suspicious_events, recent_cutoff_str)
                    current_event = {}
                elif line.strip():
                    if ":" in line:
                        key, value = line.split(":", 1)
                        current_event[key.strip()] = value.strip()
                    else:
                        if "Data" in current_event:
                            current_event["Data"] = current_event["Data"] + " " + line.strip()
                        else:
                            current_event["Data"] = line.strip()
            
            # Process last event
            if current_event:
                process_event(current_event, suspicious_events, recent_cutoff_str)
                
    except Exception as e:
        print(c(f"Error scanning event logs: {str(e)[:100]}", Color.RED))
    
    # Also try using PowerShell as alternative
    try:
        ps_script = f'''
        Get-WinEvent -FilterHashtable @{{LogName='Application'; ID=1000,1001; StartTime=(Get-Date).AddDays(-{RECENT_DAYS})}} | 
        Select-Object TimeCreated, Id, LevelDisplayName, Message | 
        ConvertTo-Json
        '''
        result = subprocess.run(
            ["powershell", "-Command", ps_script],
            capture_output=True, text=True, timeout=30
        )
        
        if result.returncode == 0 and result.stdout.strip():
            import json
            try:
                events_data = json.loads(result.stdout)
                if isinstance(events_data, list):
                    for evt in events_data:
                        process_event_ps(evt, suspicious_events)
                elif isinstance(events_data, dict):
                    process_event_ps(events_data, suspicious_events)
            except:
                pass
    except Exception as e:
        pass
    
    print(c(f"\nEvent log analysis complete. Found {len(suspicious_events)} suspicious events.",
            Color.CYAN if not suspicious_events else Color.RED))
    return suspicious_events


def process_event(event_data, suspicious_events, recent_cutoff_str):
    """Process a parsed event log entry."""
    try:
        time_str = event_data.get("TimeCreated", "")
        if not time_str:
            return
            
        # Check if event is recent
        try:
            event_time = datetime.datetime.strptime(time_str[:19], "%Y-%m-%dT%H:%M:%S")
            if event_time < datetime.datetime.strptime(recent_cutoff_str[:19], "%Y-%m-%d %H:%M:%S"):
                return
        except:
            pass
        
        message = event_data.get("Message", "")
        data = event_data.get("Data", "")
        full_text = message + " " + data
        
        # Look for suspicious patterns
        suspicious_patterns = [
            (r'crash', 'Application crash detected'),
            (r'fault', 'Fault reported'),
            (r'error', 'Error event'),
            (r'failed', 'Failure occurred'),
            (r'exception', 'Exception thrown'),
            (r'access violation', 'Access violation'),
            (r'memory', 'Memory-related issue'),
            (r'unexpected', 'Unexpected error'),
            (r'trojan', 'Potential trojan mentioned'),
            (r'virus', 'Potential virus mentioned'),
            (r'malware', 'Potential malware mentioned'),
            (r'injection', 'Code injection mentioned'),
            (r'hack', 'Hacking-related term'),
        ]
        
        reasons = []
        for pattern, reason in suspicious_patterns:
            if re.search(pattern, full_text, re.IGNORECASE):
                reasons.append(reason)
        
        if reasons:
            suspicious_events.append({
                'event_id': event_data.get('EventID', 'Unknown'),
                'time': time_str,
                'message': full_text[:200],
                'reasons': reasons
            })
            
            print(c(f"  ⚠️  FLAGGED: Event ID {event_data.get('EventID', 'Unknown')} at {time_str}", Color.RED))
            for reason in reasons:
                print(c(f"      -> {reason}", Color.YELLOW))
                
    except Exception as e:
        pass


def process_event_ps(evt, suspicious_events):
    """Process a PowerShell-queried event."""
    try:
        time_str = evt.get('TimeCreated', '')
        if not time_str:
            return
            
        event_id = evt.get('Id', '')
        message = evt.get('Message', '')
        
        if not event_id or not message:
            return
        
        # Check for suspicious patterns
        suspicious_patterns = [
            (r'crash', 'Application crash detected'),
            (r'fault', 'Fault reported'),
            (r'error', 'Error event'),
            (r'failed', 'Failure occurred'),
            (r'exception', 'Exception thrown'),
            (r'access violation', 'Access violation'),
            (r'memory', 'Memory-related issue'),
            (r'unexpected', 'Unexpected error'),
            (r'trojan', 'Potential trojan mentioned'),
            (r'virus', 'Potential virus mentioned'),
            (r'malware', 'Potential malware mentioned'),
        ]
        
        reasons = []
        for pattern, reason in suspicious_patterns:
            if re.search(pattern, message, re.IGNORECASE):
                reasons.append(reason)
        
        if reasons:
            suspicious_events.append({
                'event_id': event_id,
                'time': time_str,
                'message': message[:200],
                'reasons': reasons
            })
            
            print(c(f"  ⚠️  FLAGGED: Event ID {event_id} at {time_str}", Color.RED))
            for reason in reasons:
                print(c(f"      -> {reason}", Color.YELLOW))
                
    except Exception as e:
        pass


# ----------------------------- Section 6: DELETED FILES WITH TRACES -----------------------------

def scan_deleted_file_traces():
    """Scan for traces of deleted files (registry, shortcuts, prefetch, etc.)."""
    subheader("DELETED FILE TRACE ANALYSIS")
    
    print(c("Scanning for traces of deleted files that may no longer exist...", Color.WHITE))
    
    deleted_traces = []
    
    # 1. Check Recent Documents / Recent Items
    if platform.system() == "Windows":
        recent_folders = [
            Path(os.path.expandvars("%APPDATA%\\Microsoft\\Windows\\Recent")),
            Path(os.path.expandvars("%USERPROFILE%\\Recent")),
        ]
        
        for recent_folder in recent_folders:
            if recent_folder.exists():
                for lnk_file in recent_folder.glob("*.lnk"):
                    try:
                        # Check if the target still exists
                        target = None
                        try:
                            # Parse shortcut using PowerShell
                            ps_cmd = f'''
                            $shell = New-Object -ComObject WScript.Shell
                            $shortcut = $shell.CreateShortcut("{lnk_file}")
                            $shortcut.TargetPath
                            '''
                            result = subprocess.run(
                                ["powershell", "-Command", ps_cmd],
                                capture_output=True, text=True, timeout=5
                            )
                            if result.returncode == 0 and result.stdout.strip():
                                target = result.stdout.strip()
                        except:
                            pass
                        
                        if target and not Path(target).exists():
                            # Deleted file trace found
                            st = lnk_file.stat()
                            mod_time = st.st_mtime
                            recent_cutoff = time.time() - (RECENT_DAYS * 86400)
                            
                            if mod_time >= recent_cutoff:
                                deleted_traces.append({
                                    'type': 'Shortcut (lnk)',
                                    'name': lnk_file.name,
                                    'target': target,
                                    'modified': mod_time,
                                    'location': str(lnk_file.parent)
                                })
                                print(c(f"  ⚠️  FLAGGED: Deleted file shortcut: {target} -> {lnk_file.name}", Color.RED))
                    except Exception as e:
                        continue
    
    # 2. Check Prefetch for missing executables (only if not already scanned)
    if platform.system() == "Windows":
        windir = os.environ.get("WINDIR", "C:\\Windows")
        prefetch_dir = Path(windir) / "Prefetch"
        if prefetch_dir.exists():
            for pf_file in prefetch_dir.glob("*.pf"):
                try:
                    pf_name = pf_file.name
                    exe_name = pf_name.split("-")[0] if "-" in pf_name else pf_name.replace(".pf", "")
                    
                    # Check if the executable still exists in common locations
                    found = False
                    search_paths = [
                        Path("C:\\Program Files"),
                        Path("C:\\Program Files (x86)"),
                        Path(os.environ.get("WINDIR", "C:\\Windows")),
                        Path(os.environ.get("SYSTEMROOT", "C:\\Windows")),
                    ]
                    
                    for search_path in search_paths:
                        if search_path.exists():
                            for match in search_path.rglob(exe_name):
                                if match.is_file():
                                    found = True
                                    break
                        if found:
                            break
                    
                    if not found:
                        # Prefetch exists but executable is missing
                        st = pf_file.stat()
                        mod_time = st.st_mtime
                        recent_cutoff = time.time() - (RECENT_DAYS * 86400)
                        
                        if mod_time >= recent_cutoff:
                            deleted_traces.append({
                                'type': 'Prefetch (pf)',
                                'name': pf_file.name,
                                'target': exe_name,
                                'modified': mod_time,
                                'location': str(pf_file.parent)
                            })
                            print(c(f"  ⚠️  FLAGGED: Prefetch for missing executable: {exe_name} ({pf_file.name})", Color.RED))
                except Exception as e:
                    continue
    
    # 3. Check Windows Registry for installed programs that may have been deleted
    if platform.system() == "Windows":
        try:
            reg_keys = [
                r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
                r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
                r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            ]
            
            for reg_key in reg_keys:
                try:
                    result = subprocess.run(
                        ["reg", "query", reg_key],
                        capture_output=True, text=True, timeout=10
                    )
                    
                    if result.returncode == 0:
                        lines = result.stdout.splitlines()
                        for line in lines:
                            if line.strip() and not line.startswith("HKEY"):
                                # Check for DisplayIcon or InstallLocation that might point to deleted files
                                key_path = line.strip()
                                try:
                                    result2 = subprocess.run(
                                        ["reg", "query", f"{reg_key}\\{key_path}", "/v", "DisplayIcon"],
                                        capture_output=True, text=True, timeout=5
                                    )
                                    if result2.returncode == 0:
                                        icon_path = result2.stdout.splitlines()
                                        for icon_line in icon_path:
                                            if "REG_SZ" in icon_line or "REG_EXPAND_SZ" in icon_line:
                                                parts = icon_line.split()
                                                if len(parts) >= 3:
                                                    icon_file = parts[-1]
                                                    if not Path(icon_file).exists():
                                                        deleted_traces.append({
                                                            'type': 'Registry Uninstall Entry',
                                                            'name': key_path,
                                                            'target': icon_file,
                                                            'modified': 0,
                                                            'location': f"{reg_key}\\{key_path}"
                                                        })
                                                        print(c(f"  ⚠️  FLAGGED: Uninstall entry with missing icon: {key_path} -> {icon_file}", Color.RED))
                                except:
                                    pass
                except:
                    continue
        except:
            pass
    
    # 4. Check for empty or corrupted directories that might indicate deleted files
    try:
        drives, _ = get_all_drives()
        for drive in drives:
            # Only scan root of each drive for known deletion markers
            for root_dir in drive.glob("*"):
                try:
                    if root_dir.is_dir():
                        # Check for empty directories that are suspicious
                        try:
                            contents = list(root_dir.glob("*"))
                            if len(contents) == 0:
                                # Empty directory, might be a leftover from deletion
                                st = root_dir.stat()
                                mod_time = st.st_mtime
                                recent_cutoff = time.time() - (RECENT_DAYS * 86400)
                                if mod_time >= recent_cutoff:
                                    # Only flag if it's in a suspicious location
                                    path_str = str(root_dir).lower()
                                    suspicious_paths = ['temp', 'tmp', 'download', 'desktop', 'documents']
                                    if any(p in path_str for p in suspicious_paths):
                                        deleted_traces.append({
                                            'type': 'Empty Directory',
                                            'name': root_dir.name,
                                            'target': str(root_dir),
                                            'modified': mod_time,
                                            'location': str(root_dir.parent)
                                        })
                                        print(c(f"  ⚠️  FLAGGED: Suspicious empty directory: {root_dir}", Color.RED))
                        except:
                            pass
                except:
                    continue
    except:
        pass
    
    print(c(f"\nDeleted file trace analysis complete. Found {len(deleted_traces)} traces.",
            Color.CYAN if not deleted_traces else Color.RED))
    return deleted_traces


# ----------------------------- Section 7: Suspicious file heuristics (FULL SYSTEM SCAN) -----------------------------

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
        # Sort by most recent first
        flags.sort(key=lambda x: x[2], reverse=True)
        
        print(c(f"\n{'='*70}", Color.RED))
        print(c(f"FOUND {len(flags)} FLAGGED FILES:", Color.RED + Color.BOLD))
        print(c(f"{'='*70}", Color.RED))
        print()
        
        # Display ALL flagged files with numbering
        for idx, (f, reasons, mtime, size) in enumerate(flags, 1):
            print(c(f"[{idx}/{len(flags)}] {c('FLAGGED', Color.RED)} {f}", Color.WHITE + Color.BOLD))
            print(c(f"          Modified: {human_time(mtime)}  Size: {size/1024:.1f} KB", Color.YELLOW))
            for r in reasons:
                print(c(f"          ⚠️  {r}", Color.RED))
            print()  # Empty line between files

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
        "NOTE: This enhanced scanner includes:\n"
        "  • Prefetch analysis for suspicious executables\n"
        "  • Event Viewer (1000 & 1001) analysis for application crashes\n"
        "  • Deleted file trace detection (shortcuts, prefetch, registry)\n"
        "  • Full system file heuristics (location, hidden, double extensions)\n"
        "A flag does NOT confirm malware or cheat software. Always verify manually.",
        Color.GRAY
    ))


def main():
    enable_windows_ansi()
    os.system("")

    print_disclaimer()
    print()

    print_system_info()
    print_temp_summary()
    downloaded = print_downloads_summary()
    
    # Run all forensic scans
    prefetch_flags = scan_prefetch()
    event_flags = scan_event_logs()
    deleted_traces = scan_deleted_file_traces()
    file_flags = scan_suspicious_full(downloaded)

    header("FINAL SUMMARY")
    total_flags = len(prefetch_flags) + len(event_flags) + len(deleted_traces) + len(file_flags)
    
    print(c("\nForensic Scan Results:", Color.CYAN + Color.BOLD))
    print(c(f"  • Prefetch flags:    {len(prefetch_flags)}", Color.WHITE))
    print(c(f"  • Event log flags:   {len(event_flags)}", Color.WHITE))
    print(c(f"  • Deleted traces:    {len(deleted_traces)}", Color.WHITE))
    print(c(f"  • File heuristics:   {len(file_flags)}", Color.WHITE))
    print(c(f"  • Total flags:       {total_flags}", Color.WHITE + Color.BOLD))
    
    if total_flags > 0:
        print("")
        print(c("⚠️  REVIEW RECOMMENDED: Investigate flagged items above.", Color.RED + Color.BOLD))
    else:
        print("")
        print(c("✅ No significant flags raised. System appears clean by these heuristics.", Color.GREEN + Color.BOLD))
    
    print(c("\nFull forensic scan complete.\n", Color.WHITE))


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(c("\nScan interrupted by user.", Color.YELLOW))
        sys.exit(1)
    except Exception as e:
        print(c(f"\nUnexpected error: {e}", Color.RED))
        sys.exit(1)
