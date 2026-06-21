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
    By Hidan scripts v1.6
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


# ----------------------------- Section 4: Suspicious file heuristics (FULL SYSTEM SCAN) -----------------------------

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
        "NOTE: This tool uses generic heuristics (location, hidden attribute,\n"
        "recent modification, double extensions). A flag does NOT confirm malware\n"
        "or cheat software -- it only means the file matches a pattern worth your\n"
        "own review. Always verify manually before deleting anything.\n"
        "This version scans ALL drives thoroughly (skipping critical system dirs).",
        Color.GRAY
    ))


def main():
    enable_windows_ansi()
    os.system("")

    print(c("\n HIDAN SCRIPT FULL SYSTEM SCANNER\n", Color.CYAN + Color.BOLD))
    print_disclaimer()
    print()

    print_system_info()
    print_temp_summary()
    downloaded = print_downloads_summary()
    flags = scan_suspicious_full(downloaded)

    header("SUMMARY")
    if flags:
        print("")
        print(c(f"{len(flags)} file(s) flagged for review.", Color.RED + Color.BOLD))
    else:
        print("")
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
