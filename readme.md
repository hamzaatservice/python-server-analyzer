# Server Resource Analyzer

A cross-platform Python utility that generates a comprehensive snapshot of server health, storage usage, and process-level resource consumption.  
Designed for **quick diagnostics**, capacity planning, and troubleshooting on Linux, macOS, and Windows systems.

---

## Features

✅ **System Overview**
- OS, kernel/version, architecture
- CPU cores (physical & logical), frequency
- RAM and swap usage
- System boot time

✅ **Disk Analysis**
- Mounted partitions with usage %
- Automatic warnings for disks above configurable thresholds
- Human-readable size formatting

✅ **Directory Storage Scan**
- Recursively scans top-level directories
- Identifies the largest space consumers
- Configurable depth, size thresholds, and result limits
- Optimized to skip inaccessible paths

✅ **Process Resource Analysis**
- Top processes by CPU usage
- Top processes by memory usage
- Automatic flagging of high CPU / high memory processes

✅ **File Handle Pressure Detection**
- Lists processes with the most open file descriptors
- Useful for diagnosing leaks and OS-level limits

✅ **Network I/O Snapshot**
- Per-interface cumulative traffic statistics
- Packet counts, errors, and drops

✅ **Disk I/O per Process**
- Read/write I/O totals per process
- Linux-supported (gracefully degrades elsewhere)

✅ **Actionable Summary**
- Highlights critical issues
- Provides quick recommendations at the end of the report

✅ **Exportable Report**
- Saves the full output to `server_report.txt` for audits or sharing

---

## Requirements

- Python **3.8+**
- Dependencies:
  ```bash
  pip install psutil tabulate
