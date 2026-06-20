#!/usr/bin/env python3
"""
Local System Inspector
-----------------------
A stdlib-only diagnostic tool that runs ON THIS MACHINE to summarize:
  1. Basic system info (OS, install date)
  2. Temp / admin temp file counts
  3. Recently downloaded files
  4. Generic suspicious-file heuristics (unsigned-looking, hidden, recently
     modified executables in odd locations)

This is a self-audit tool. It does NOT identify specific cheat software by
name/signature, does not modify or delete anything, and does not transmit
data anywhere. It only reads file metadata on the local filesystem.

Run with:  python scan.py
No third-party packages required (stdlib only).
"""

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
    YELLOW = "\033[93m"
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

SUSPICIOUS_EXTENSIONS = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs"}

# Heuristic thresholds
RECENT_DAYS = 7
MAX_LIST = 25


def human_time(ts):
    try:
        return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return "unknown"


def safe_walk(root, max_depth=4):
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
    else:
        dirs.append(("Temp", "/tmp"))
        dirs.append(("Var Tmp", "/var/tmp"))
    return dirs


def print_temp_summary():
    subheader("TEMPORARY / ADMIN TEMP FILES")
    total = 0
    for label, path in get_temp_dirs():
        count = 0
        for _ in safe_walk(path, max_depth=2):
            count += 1
        total += count
        print(c(f"{label} ({path}): {count} files", Color.WHITE))
    print(c(f"Total temp files found: {total}", Color.WHITE + Color.BOLD))


# ----------------------------- Section 3: Downloaded files -----------------------------

def get_downloads_dir():
    home = Path.home()
    candidates = [home / "Downloads"]
    return [p for p in candidates if p.exists()]


def print_downloads_summary():
    subheader("DOWNLOADED FILES")
    all_files = []
    for d in get_downloads_dir():
        for f in safe_walk(d, max_depth=3):
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


# ----------------------------- Section 4: Suspicious file heuristics -----------------------------

def is_windows_signed_unverifiable():
    """We don't shell out to signtool (not always present); this is a
    placeholder that always returns 'unknown' so we never falsely claim
    something is unsigned without real verification."""
    return None


def scan_suspicious(downloaded_files):
    subheader("SUSPICIOUS FILE TRACES (heuristic flags)")
    flags = []
    notices = []

    scan_roots = []
    for d in get_downloads_dir():
        scan_roots.append(d)
    for label, path in get_temp_dirs():
        scan_roots.append(Path(path))

    now = time.time()
    recent_cutoff = now - (RECENT_DAYS * 86400)

    seen = set()
    for root in scan_roots:
        for f in safe_walk(root, max_depth=3):
            if not f.is_file():
                continue
            key = str(f.resolve()) if f.exists() else str(f)
            if key in seen:
                continue
            seen.add(key)

            ext = f.suffix.lower()
            if ext not in SUSPICIOUS_EXTENSIONS:
                continue

            try:
                st = f.stat()
            except Exception:
                continue

            reasons = []

            # Heuristic 1: executable sitting directly in a temp directory
            path_str = str(f).lower()
            if "temp" in path_str and ext in (".exe", ".scr", ".dll"):
                reasons.append("Executable located in a temp directory")

            # Heuristic 2: hidden file (Unix dotfile, or Windows hidden attrib)
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

            # Heuristic 3: recently modified (within RECENT_DAYS)
            recently_modified = st.st_mtime >= recent_cutoff
            if recently_modified and ext in (".exe", ".dll", ".scr"):
                reasons.append(f"Executable modified within last {RECENT_DAYS} days")

            # Heuristic 4: double extension trick e.g. "setup.pdf.exe"
            if f.name.lower().count(".") >= 2 and ext == ".exe":
                stem_parts = f.name.lower().split(".")
                if len(stem_parts) >= 3 and stem_parts[-2] in (
                    "pdf", "jpg", "png", "doc", "docx", "txt", "mp3", "mp4"
                ):
                    reasons.append("Double file extension (disguise pattern)")

            # Heuristic 5: script files that auto-run in odd places (.bat/.vbs/.ps1 in temp)
            if ext in (".bat", ".vbs", ".ps1", ".cmd") and "temp" in path_str:
                reasons.append("Script file in temp directory (possible dropper/launcher)")

            if reasons:
                flags.append((f, reasons, st.st_mtime, st.st_size))
            else:
                notices.append(f)

    if not flags:
        print(c("No suspicious indicators found based on current heuristics.", Color.YELLOW))
    else:
        flags.sort(key=lambda x: x[2], reverse=True)
        for f, reasons, mtime, size in flags:
            print(c(f"[FLAGGED] {f}", Color.RED + Color.BOLD))
            print(c(f"          Modified: {human_time(mtime)}  Size: {size/1024:.1f} KB", Color.RED))
            for r in reasons:
                print(c(f"          -> {r}", Color.RED))

    print()
    print(c(f"Executable/script files scanned without flags: {len(notices)}", Color.YELLOW))
    if notices:
        print(c("Sample (up to 10):", Color.YELLOW))
        for f in notices[:10]:
            print(c(f"  {f}", Color.YELLOW))

    return flags


# ----------------------------- Main -----------------------------

def print_disclaimer():
    print(c(
        "NOTE: This tool uses generic heuristics (location, hidden attribute,\n"
        "recent modification, double extensions). A flag does NOT confirm malware\n"
        "or cheat software -- it only means the file matches a pattern worth your\n"
        "own review. Always verify manually before deleting anything.",
        Color.GRAY
    ))


def main():
    enable_windows_ansi()
    os.system("")  # also helps enable ANSI on some Windows terminals

    print(c("\n  LOCAL SYSTEM INSPECTOR\n", Color.CYAN + Color.BOLD))
    print_disclaimer()
    print()

    print_system_info()
    print_temp_summary()
    downloaded = print_downloads_summary()
    flags = scan_suspicious(downloaded)

    header("SUMMARY")
    if flags:
        print(c(f"{len(flags)} file(s) flagged for review.", Color.RED + Color.BOLD))
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
