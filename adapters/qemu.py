"""QEMU / KVM environment inspection for the local repro VM workflow.

Pure inspection: it reports whether a QEMU system emulator and KVM acceleration
are available and how much memory/disk the host has. It never boots a VM, builds
an image, or downloads anything. The `env init` scaffolding writes the actual
boot script that the researcher reviews and runs.

Note: in WSL2, KVM may or may not be exposed. This module reports the real state
and never assumes acceleration is present.
"""
from __future__ import annotations

import os
import shutil
import stat


QEMU_BINARIES = ("qemu-system-x86_64", "qemu-system-aarch64")


def kvm_status() -> dict:
    path = "/dev/kvm"
    present = os.path.exists(path)
    readable = writable = False
    if present:
        try:
            st = os.stat(path)
            present = stat.S_ISCHR(st.st_mode)
            readable = os.access(path, os.R_OK)
            writable = os.access(path, os.W_OK)
        except OSError:
            present = False
    return {"present": present, "readable": readable, "writable": writable, "accelerated": present and readable and writable}


def qemu_status() -> dict:
    found = {name: shutil.which(name) for name in QEMU_BINARIES}
    return {"binaries": {k: v for k, v in found.items() if v}, "available": any(found.values())}


def host_resources() -> dict:
    out: dict = {}
    try:
        total = os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
        out["total_memory_gb"] = round(total / 1024**3, 2)
    except (ValueError, OSError):
        out["total_memory_gb"] = None
    try:
        avail_pages = os.sysconf("SC_AVPHYS_PAGES")
        out["available_memory_gb"] = round(avail_pages * os.sysconf("SC_PAGE_SIZE") / 1024**3, 2)
    except (ValueError, OSError):
        out["available_memory_gb"] = None
    out["cpu_count"] = os.cpu_count()
    return out


def disk_free_gb(path: str = ".") -> float | None:
    try:
        usage = shutil.disk_usage(path)
        return round(usage.free / 1024**3, 2)
    except OSError:
        return None


def status(path: str = ".") -> dict:
    kvm = kvm_status()
    qemu = qemu_status()
    res = host_resources()
    limitation = None
    if qemu["available"] and not kvm["accelerated"]:
        limitation = (
            "KVM acceleration is unavailable or inaccessible. QEMU will run under TCG "
            "(software emulation), which is far slower. Use a host or an isolated VM with "
            "/dev/kvm exposed for dynamic repro; see the generated env's FETCH.md/README."
        )
    elif not qemu["available"]:
        limitation = "No QEMU system emulator found; install qemu-system-x86_64 for local repro."
    return {
        "qemu": qemu,
        "kvm": kvm,
        "resources": res,
        "disk_free_gb": disk_free_gb(path),
        "limitation": limitation,
    }
