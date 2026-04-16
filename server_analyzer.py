#!/usr/bin/env python3
"""
Server Resource Analyzer
Analyzes storage usage, service resource consumption, and system specs.
Requires: psutil, tabulate  ->  pip install psutil tabulate
"""

import os
import sys
import time
import shutil
import platform
import subprocess
import threading
from datetime import datetime
from pathlib import Path

try:
    import psutil
except ImportError:
    print("[ERROR] psutil not installed. Run: pip install psutil")
    sys.exit(1)

try:
    from tabulate import tabulate
    HAS_TABULATE = True
except ImportError:
    HAS_TABULATE = False

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────
SCAN_ROOTS = {
    "Windows": ["C:\\"],
    "Linux":   ["/", "/home", "/var", "/tmp", "/opt"],
    "Darwin":  ["/", "/Users", "/var", "/tmp"],
}
MAX_DEPTH_QUICK   = 3   # fast top-level scan
MAX_DIR_RESULTS   = 25  # top N directories to report
MIN_DIR_SIZE_MB   = 10  # skip dirs smaller than this
CPU_SAMPLE_SEC    = 2   # how long to measure CPU
REPORT_FILE       = "server_report.txt"
HIGH_CPU_THRESH   = 10.0   # % — flag processes above this
HIGH_MEM_THRESH   = 200    # MB — flag processes above this
HIGH_DISK_THRESH  = 85.0   # % — flag partitions above this

# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def bytes_to_human(n_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n_bytes < 1024:
            return f"{n_bytes:.2f} {unit}"
        n_bytes /= 1024
    return f"{n_bytes:.2f} PB"


def separator(char="-", width=72) -> str:
    return char * width


def section(title: str) -> str:
    line = separator()
    return f"\n{line}\n  {title}\n{line}"


def _print(text: str, out_lines: list):
    print(text)
    out_lines.append(text)


def table(headers: list, rows: list, fmt="simple") -> str:
    if HAS_TABULATE:
        return tabulate(rows, headers=headers, tablefmt=fmt)
    # plain fallback
    col_w = [max(len(str(h)), max((len(str(r[i])) for r in rows), default=0))
             for i, h in enumerate(headers)]
    fmt_row = lambda r: "  ".join(str(r[i]).ljust(col_w[i]) for i in range(len(headers)))
    lines = [fmt_row(headers), "  ".join("-" * w for w in col_w)]
    lines += [fmt_row(r) for r in rows]
    return "\n".join(lines)


# ─────────────────────────────────────────────
#  1. SYSTEM SPECS
# ─────────────────────────────────────────────

def get_system_specs() -> dict:
    uname = platform.uname()
    cpu_freq = psutil.cpu_freq()
    mem = psutil.virtual_memory()
    swap = psutil.swap_memory()
    boot_ts = datetime.fromtimestamp(psutil.boot_time())

    return {
        "OS":           f"{uname.system} {uname.release} ({uname.version})",
        "Hostname":     uname.node,
        "Architecture": uname.machine,
        "Processor":    uname.processor or platform.processor(),
        "CPU Cores (Physical)": psutil.cpu_count(logical=False),
        "CPU Cores (Logical)":  psutil.cpu_count(logical=True),
        "CPU Max Freq":  f"{cpu_freq.max:.0f} MHz" if cpu_freq else "N/A",
        "Total RAM":     bytes_to_human(mem.total),
        "Available RAM": bytes_to_human(mem.available),
        "RAM Usage %":   f"{mem.percent}%",
        "Total Swap":    bytes_to_human(swap.total),
        "Swap Usage %":  f"{swap.percent}%",
        "Boot Time":     boot_ts.strftime("%Y-%m-%d %H:%M:%S"),
    }


# ─────────────────────────────────────────────
#  2. DISK PARTITIONS
# ─────────────────────────────────────────────

def get_disk_info() -> list:
    rows = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except PermissionError:
            continue
        flag = " *** HIGH ***" if usage.percent >= HIGH_DISK_THRESH else ""
        rows.append([
            part.device,
            part.mountpoint,
            part.fstype,
            bytes_to_human(usage.total),
            bytes_to_human(usage.used),
            bytes_to_human(usage.free),
            f"{usage.percent:.1f}%{flag}",
        ])
    return rows


# ─────────────────────────────────────────────
#  3. DIRECTORY SIZE SCAN
# ─────────────────────────────────────────────

def _dir_size(path: str, max_depth: int, current_depth: int = 0) -> int:
    """Recursively compute directory size (fast, skips inaccessible paths)."""
    total = 0
    try:
        with os.scandir(path) as it:
            for entry in it:
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat(follow_symlinks=False).st_size
                    elif entry.is_dir(follow_symlinks=False):
                        if current_depth < max_depth:
                            total += _dir_size(entry.path, max_depth, current_depth + 1)
                except (PermissionError, OSError):
                    pass
    except (PermissionError, OSError):
        pass
    return total


def scan_directories(roots: list, max_depth: int = MAX_DEPTH_QUICK) -> list:
    """Return list of (path, size_bytes) for all subdirs under roots."""
    results = []

    def _walk(base: str, depth: int):
        if depth > max_depth:
            return
        try:
            with os.scandir(base) as it:
                for entry in it:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    try:
                        sz = _dir_size(entry.path, max_depth - depth)
                        if sz >= MIN_DIR_SIZE_MB * 1024 * 1024:
                            results.append((entry.path, sz))
                        _walk(entry.path, depth + 1)
                    except (PermissionError, OSError):
                        pass
        except (PermissionError, OSError):
            pass

    for root in roots:
        if os.path.isdir(root):
            print(f"  Scanning {root} …", flush=True)
            _walk(root, 0)

    results.sort(key=lambda x: x[1], reverse=True)
    return results[:MAX_DIR_RESULTS]


# ─────────────────────────────────────────────
#  4. SERVICE / PROCESS ANALYSIS
# ─────────────────────────────────────────────

def get_top_processes() -> tuple:
    """Return (cpu_rows, mem_rows, flagged_rows)."""
    procs = []
    for p in psutil.process_iter(["pid", "name", "username", "status"]):
        try:
            with p.oneshot():
                cpu  = p.cpu_percent(interval=None)
                mem  = p.memory_info().rss
                procs.append({
                    "pid":    p.pid,
                    "name":   p.name(),
                    "user":   p.username() if hasattr(p, 'username') else "N/A",
                    "status": p.status(),
                    "cpu":    cpu,
                    "mem_mb": mem / (1024 * 1024),
                })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    # Prime CPU counters then sample again
    time.sleep(CPU_SAMPLE_SEC)
    for item in procs:
        try:
            p = psutil.Process(item["pid"])
            item["cpu"] = p.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    top_cpu = sorted(procs, key=lambda x: x["cpu"],    reverse=True)[:15]
    top_mem = sorted(procs, key=lambda x: x["mem_mb"], reverse=True)[:15]

    flagged = [
        p for p in procs
        if p["cpu"] >= HIGH_CPU_THRESH or p["mem_mb"] >= HIGH_MEM_THRESH
    ]
    flagged.sort(key=lambda x: x["cpu"], reverse=True)

    def fmt_rows(lst):
        return [
            [p["pid"], p["name"][:35], p["user"][:20],
             f"{p['cpu']:.1f}%", f"{p['mem_mb']:.1f} MB", p["status"]]
            for p in lst
        ]

    return fmt_rows(top_cpu), fmt_rows(top_mem), fmt_rows(flagged)


# ─────────────────────────────────────────────
#  5. OPEN FILE HANDLES (storage pressure clue)
# ─────────────────────────────────────────────

def get_open_file_stats() -> list:
    """Top processes by open file handle count."""
    counts = {}
    for p in psutil.process_iter(["pid", "name"]):
        try:
            n = p.num_fds() if hasattr(p, "num_fds") else len(p.open_files())
            counts[p.pid] = (p.name(), n)
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass
    sorted_counts = sorted(counts.items(), key=lambda x: x[1][1], reverse=True)[:10]
    return [[pid, name, count] for pid, (name, count) in sorted_counts]


# ─────────────────────────────────────────────
#  6. NETWORK I/O SNAPSHOT
# ─────────────────────────────────────────────

def get_network_io() -> list:
    net = psutil.net_io_counters(pernic=True)
    rows = []
    for nic, stats in net.items():
        rows.append([
            nic,
            bytes_to_human(stats.bytes_sent),
            bytes_to_human(stats.bytes_recv),
            stats.packets_sent,
            stats.packets_recv,
            stats.errin + stats.errout,
            stats.dropin + stats.dropout,
        ])
    return rows


# ─────────────────────────────────────────────
#  7. DISK I/O PER PROCESS (Linux only)
# ─────────────────────────────────────────────

def get_disk_io_processes() -> list:
    rows = []
    for p in psutil.process_iter(["pid", "name"]):
        try:
            io = p.io_counters()
            total = io.read_bytes + io.write_bytes
            if total > 0:
                rows.append([p.pid, p.name()[:35],
                              bytes_to_human(io.read_bytes),
                              bytes_to_human(io.write_bytes),
                              bytes_to_human(total)])
        except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
            pass
    rows.sort(key=lambda x: x[4], reverse=True)
    return rows[:15]


# ─────────────────────────────────────────────
#  MAIN REPORT
# ─────────────────────────────────────────────

def run_analysis(quick: bool = False):
    out = []
    ts  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    sys_name = platform.system()
    roots = SCAN_ROOTS.get(sys_name, ["/"])

    _print(f"\n{'=' * 72}", out)
    _print(f"  SERVER RESOURCE ANALYZER  --  {ts}", out)
    _print(f"  Platform: {sys_name}", out)
    _print(f"{'=' * 72}", out)

    # ── 1. System specs ──────────────────────────────────────────
    _print(section("1. SYSTEM SPECIFICATIONS"), out)
    specs = get_system_specs()
    for k, v in specs.items():
        _print(f"  {k:<30} {v}", out)

    # ── 2. Disk partitions ───────────────────────────────────────
    _print(section("2. DISK PARTITIONS  (*** = above 85% full)"), out)
    disk_rows = get_disk_info()
    hdr = ["Device", "Mount", "FS", "Total", "Used", "Free", "Use%"]
    _print(table(hdr, disk_rows), out)

    # ── 3. Directory storage scan ────────────────────────────────
    depth = 2 if quick else MAX_DEPTH_QUICK
    _print(section(f"3. TOP {MAX_DIR_RESULTS} STORAGE-HEAVY DIRECTORIES  (depth={depth})"), out)
    _print("  Scanning … this may take a moment.", out)
    dir_results = scan_directories(roots, max_depth=depth)
    if dir_results:
        dir_rows = [[bytes_to_human(sz), path] for path, sz in dir_results]
        _print(table(["Size", "Directory"], dir_rows), out)
    else:
        _print("  No directories found above threshold.", out)

    # ── 4. CPU top processes ─────────────────────────────────────
    _print(section("4. TOP PROCESSES  (sampling CPU for a few seconds …)"), out)
    hdr_p = ["PID", "Name", "User", "CPU %", "MEM (MB)", "Status"]
    cpu_rows, mem_rows, flagged_rows = get_top_processes()

    _print("\n  [4a] Top by CPU:", out)
    _print(table(hdr_p, cpu_rows), out)

    _print("\n  [4b] Top by Memory:", out)
    _print(table(hdr_p, mem_rows), out)

    if flagged_rows:
        _print(f"\n  [4c] FLAGGED PROCESSES  (CPU > {HIGH_CPU_THRESH}% or MEM > {HIGH_MEM_THRESH} MB):", out)
        _print(table(hdr_p, flagged_rows), out)
    else:
        _print(f"\n  [4c] No processes exceeded thresholds "
               f"(CPU > {HIGH_CPU_THRESH}% or MEM > {HIGH_MEM_THRESH} MB).", out)

    # ── 5. Open file handles ─────────────────────────────────────
    _print(section("5. TOP PROCESSES BY OPEN FILE HANDLES"), out)
    fh_rows = get_open_file_stats()
    if fh_rows:
        _print(table(["PID", "Name", "Open Handles"], fh_rows), out)
    else:
        _print("  Could not retrieve file handle info.", out)

    # ── 6. Network I/O ───────────────────────────────────────────
    _print(section("6. NETWORK I/O (cumulative since boot)"), out)
    net_hdr = ["Interface", "Sent", "Received", "Pkts Sent", "Pkts Recv", "Errors", "Drops"]
    _print(table(net_hdr, get_network_io()), out)

    # ── 7. Per-process disk I/O ──────────────────────────────────
    _print(section("7. TOP PROCESSES BY DISK I/O (cumulative since start)"), out)
    io_rows = get_disk_io_processes()
    if io_rows:
        _print(table(["PID", "Name", "Read", "Written", "Total I/O"], io_rows), out)
    else:
        _print("  Disk I/O per-process not available on this platform.", out)

    # ── 8. Summary & Recommendations ────────────────────────────
    _print(section("8. SUMMARY & RECOMMENDATIONS"), out)

    issues = []
    for row in disk_rows:
        if "HIGH" in row[-1]:
            issues.append(f"  [DISK]    Partition {row[1]} is {row[-1].strip()} — "
                          f"clean up or expand storage.")

    if dir_results:
        top3 = dir_results[:3]
        issues.append(f"  [STORAGE] Largest directories consuming space:")
        for path, sz in top3:
            issues.append(f"            {bytes_to_human(sz):>10}  {path}")

    if flagged_rows:
        issues.append(f"  [PROCESS] High-resource processes detected:")
        for r in flagged_rows[:5]:
            issues.append(f"            PID {r[0]:<6} {r[1]:<35} CPU={r[3]}  MEM={r[4]}")

    mem = psutil.virtual_memory()
    if mem.percent > 85:
        issues.append(f"  [MEMORY]  RAM usage is {mem.percent:.1f}% — "
                      f"consider adding swap or freeing memory.")
    if mem.percent > 70:
        issues.append(f"  [MEMORY]  RAM usage is {mem.percent:.1f}% — watch for pressure.")

    if issues:
        for issue in issues:
            _print(issue, out)
    else:
        _print("  No critical issues detected.", out)

    _print(f"\n  Analysis complete at {datetime.now().strftime('%H:%M:%S')}", out)
    _print("=" * 72, out)

    # ── Save report ──────────────────────────────────────────────
    report_path = Path(__file__).parent / REPORT_FILE
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out))
    print(f"\n  Report saved to: {report_path}")


# ─────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    # Ensure UTF-8 output on Windows terminals
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    quick_mode = "--quick" in sys.argv or "-q" in sys.argv
    if quick_mode:
        print("  Running in QUICK mode (shallow scan).")
    run_analysis(quick=quick_mode)
