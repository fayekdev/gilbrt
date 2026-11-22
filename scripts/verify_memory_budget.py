"""Run an authorized audit in a Windows job with a combined commit-memory cap.

This measures the actual website/model path; it does not emulate the OS or CPU of
a low-end device. File-backed resident pages are measured separately from commit.
"""

import argparse
import ctypes
import json
import os
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

from gilbrt.bundled_ai import peak_memory_bytes


class BasicLimits(ctypes.Structure):
    """JOBOBJECT_BASIC_LIMIT_INFORMATION."""
    _fields_ = [("process_time", ctypes.c_longlong), ("job_time", ctypes.c_longlong), ("flags", wintypes.DWORD),
                ("minimum_ws", ctypes.c_size_t), ("maximum_ws", ctypes.c_size_t), ("active", wintypes.DWORD),
                ("affinity", ctypes.c_size_t), ("priority", wintypes.DWORD), ("scheduling", wintypes.DWORD)]


class IOCounts(ctypes.Structure):
    """IO_COUNTERS."""
    _fields_ = [(name, ctypes.c_ulonglong) for name in ("read_ops", "write_ops", "other_ops", "read_bytes", "write_bytes", "other_bytes")]


class Limits(ctypes.Structure):
    """JOBOBJECT_EXTENDED_LIMIT_INFORMATION."""
    _fields_ = [("basic", BasicLimits), ("io", IOCounts), ("process_limit", ctypes.c_size_t),
                ("job_limit", ctypes.c_size_t), ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]


class ProcessList(ctypes.Structure):
    """JOBOBJECT_BASIC_PROCESS_ID_LIST with space for 64 process IDs."""
    _fields_ = [("assigned", wintypes.DWORD), ("count", wintypes.DWORD), ("ids", ctypes.c_size_t * 64)]


def main() -> int:
    """Apply a cap before spawning gilbrt; descendants inherit the job limits."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--confirm-authorized", required=True, action="store_true")
    parser.add_argument("--limit-mb", default=1024, type=int)
    args = parser.parse_args()
    if os.name != "nt" or not 768 <= args.limit_mb <= 2048:
        parser.error("This verifier needs Windows and --limit-mb between 768 and 2048")
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
    kernel.CreateJobObjectW.restype = wintypes.HANDLE
    kernel.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel.QueryInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p]
    kernel.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    job = kernel.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError(ctypes.get_last_error())
    limits = Limits()
    limits.basic.flags = 0x200  # JOB_OBJECT_LIMIT_JOB_MEMORY: combined committed bytes.
    limits.job_limit = args.limit_mb * 1024 * 1024
    if not kernel.SetInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
        raise ctypes.WinError(ctypes.get_last_error())
    if not kernel.AssignProcessToJobObject(job, kernel.GetCurrentProcess()):
        raise ctypes.WinError(ctypes.get_last_error())
    root = Path(__file__).resolve().parents[1]
    audit = root / ".runtime" / "budget-audit.json"
    peaks = {}
    started = time.monotonic()
    child = subprocess.Popen([sys.executable, "-m", "gilbrt", "--url", args.url, "--confirm-authorized",
        "--search", "passwords,access-codes", "--local-model", "bundled", "--output", str(audit), "--format", "json"],
        cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        while child.poll() is None:
            processes = ProcessList()
            if not kernel.QueryInformationJobObject(job, 3, ctypes.byref(processes), ctypes.sizeof(processes), None):
                raise ctypes.WinError(ctypes.get_last_error())
            for pid in processes.ids[:processes.count]:
                peak = peak_memory_bytes(pid)
                if peak is not None:
                    peaks[pid] = max(peaks.get(pid, 0), peak)
            if time.monotonic() - started > 240:
                child.terminate()
                raise TimeoutError("Budgeted audit exceeded 240 seconds")
            time.sleep(0.1)
        if not kernel.QueryInformationJobObject(job, 9, ctypes.byref(limits), ctypes.sizeof(limits), None):
            raise ctypes.WinError(ctypes.get_last_error())
        report = json.loads(audit.read_text()) if child.returncode == 0 else {}
        ai = report.get("metadata", {}).get("local_ai", {})
        summary = {"exit_code": child.returncode, "seconds": round(time.monotonic() - started, 2),
            "combined_commit_limit_bytes": limits.job_limit, "peak_job_committed_bytes": limits.peak_job,
            "sum_observed_process_peak_rss_bytes": sum(peaks.values()), "observed_processes": len(peaks),
            "resources_scanned": report.get("metadata", {}).get("resources_scanned", 0), "local_ai": ai,
            "model_findings": sum(f["title"].startswith("Model-reviewed") for f in report.get("findings", [])),
            "passed": child.returncode == 0 and bool(ai.get("chunks_analyzed")) and not ai.get("failed") and sum(peaks.values()) < 1024 ** 3,
            "limitations": "Commit limit covers verifier, gilbrt and inherited runner processes; RSS is sampled separately. OS RAM, CPU speed and actual 2-GB hardware are not emulated."}
        (root / ".runtime" / "memory-budget.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary, indent=2))
        return 0 if summary["passed"] else 1
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait(timeout=10)
        kernel.CloseHandle(job)


if __name__ == "__main__":
    raise SystemExit(main())
