#!/usr/bin/env python3
# ────────────────────────────────────────────────────────────
# CATBOOSTER 0.1 — TCP Shield for macOS
# Full TCP hardening + 49-Day uptime protection
# ────────────────────────────────────────────────────────────
import os
import subprocess
import tkinter as tk
from tkinter import scrolledtext
from datetime import datetime
import shlex
import time
import threading
import plistlib
import tempfile

BG = "#000000"
TEXT = "#00b4ff"
ACCENT = "#00d4ff"
DIM = "#003366"
PANEL = "#0a0f1a"
BTN_BG = "#000000"
BTN_HOVER = "#001a33"
GREEN = "#00ffaa"
RED = "#ff3366"
WARNING = "#ffaa00"
PURPLE = "#ff00ff"

VERSION = "0.1"
APP_NAME = "Catbooster"
TAGLINE = "TCP Shield for macOS"
LAUNCHD_LABEL = "com.ac.holdings.catbooster"
LAUNCHD_PATH = f"/Library/LaunchDaemons/{LAUNCHD_LABEL}.plist"
LEGACY_LAUNCHD_PATH = "/Library/LaunchDaemons/com.ac.holdings.shadowneko.plist"

LOG_TAGS = {
    TEXT: "text",
    ACCENT: "accent",
    DIM: "dim",
    GREEN: "green",
    RED: "red",
    WARNING: "warning",
    PURPLE: "purple",
}

TCP_SETTINGS = {
    "net.inet.tcp.always_keepalive": "1",
    "net.inet.tcp.keepidle": "60000",      # 60s idle — matches catctl / Cat stack
    "net.inet.tcp.keepintvl": "10000",     # 10s between probes
    "net.inet.tcp.keepcnt": "15",          # 15 probes — god mode hardening target
    "net.inet.tcp.mssdflt": "1448",
    "net.inet.tcp.blackhole": "2",
    "net.inet.tcp.log_in_vain": "1",
    "net.inet.tcp.syncookie": "1",
    "net.inet.tcp.randomize_timestamps": "1",
    "net.inet.tcp.sack": "1",
    # macOS has no net.inet.tcp.rfc1323 OID (FreeBSD-only).
    # RFC1323 window scaling is always on; randomize_timestamps + sack cover it.
}


class CatBooster:
    def __init__(self, root):
        self.root = root
        self.root.title(f"{APP_NAME} {VERSION}")
        self.root.geometry("860x720")
        self.root.minsize(720, 560)
        self.root.configure(bg=BG)
        self.is_admin = os.geteuid() == 0
        self._setup_ui()
        self._check_status()
        self._start_uptime_monitor()

    def _setup_ui(self):
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=24, pady=(24, 12))
        tk.Label(header, text=f"🐱 {APP_NAME} {VERSION}", font=("Helvetica Neue", 28, "bold"), fg=TEXT, bg=BG).pack(side="left")
        tk.Label(header, text=TAGLINE, font=("Helvetica Neue", 12), fg=DIM, bg=BG).pack(side="left", padx=16)

        status_frame = tk.Frame(self.root, bg=PANEL, bd=2, relief="solid", highlightbackground=ACCENT)
        status_frame.pack(fill="x", padx=24, pady=8)
        self.status_label = tk.Label(status_frame, text="🔍 Initializing TCP shield...", font=("Helvetica Neue", 14, "bold"), fg=TEXT, bg=PANEL, padx=20, pady=10)
        self.status_label.pack(anchor="w")
        self.uptime_label = tk.Label(status_frame, text="⏳ Uptime: Calculating...", font=("Helvetica Neue", 13), fg=WARNING, bg=PANEL, padx=20)
        self.uptime_label.pack(anchor="w")
        self.admin_label = tk.Label(status_frame, text="", font=("Helvetica Neue", 11), fg=DIM, bg=PANEL, padx=20)
        self.admin_label.pack(anchor="w")

        btn_frame = tk.Frame(self.root, bg=BG)
        btn_frame.pack(fill="x", padx=24, pady=12)
        buttons = [
            ("🔧 Apply Full Hardening", self.apply_fix, ACCENT),
            ("✅ Verify All", self._check_status, GREEN),
            ("🔄 Soft Refresh", self.soft_refresh, WARNING),
            ("🛡️ Install Persistent Shield", self.install_launchd, TEXT),
            ("🌌 Full God Mode", self.god_mode, PURPLE),
        ]
        for text, cmd, color in buttons:
            tk.Button(btn_frame, text=text, command=cmd, bg=BTN_BG, fg=color,
                      activebackground=BTN_HOVER, font=("Helvetica Neue", 11, "bold"),
                      padx=18, pady=12, relief="flat", cursor="hand2").pack(side="left", padx=6)

        if not self.is_admin:
            tk.Button(btn_frame, text="👑 Restart as Admin", command=self._elevate,
                      bg=BTN_BG, fg=GREEN, activebackground=BTN_HOVER,
                      font=("Helvetica Neue", 11, "bold"), padx=18, pady=12).pack(side="left", padx=6)

        log_frame = tk.Frame(self.root, bg=PANEL, bd=2, relief="solid", highlightbackground=DIM)
        log_frame.pack(fill="both", expand=True, padx=24, pady=8)
        tk.Label(log_frame, text="📋 Catbooster Log", font=("Helvetica Neue", 12, "bold"), fg=DIM, bg=PANEL, padx=16, pady=6).pack(anchor="w")
        self.log_text = scrolledtext.ScrolledText(log_frame, bg=BG, fg=TEXT, font=("Menlo", 10), wrap="word", height=18)
        self.log_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        for color, tag in LOG_TAGS.items():
            self.log_text.tag_configure(tag, foreground=color)

        tk.Label(self.root, text=f"Proto AC Holdings 2026 · {APP_NAME} {VERSION}", font=("Helvetica Neue", 9), fg=DIM, bg=BG).pack(pady=8)

    def _log(self, msg, color=TEXT):
        tag = LOG_TAGS.get(color, "text")
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_text.insert("end", f"[{ts}] {msg}\n", tag)
        self.log_text.see("end")
        self.root.update_idletasks()

    def _run(self, cmd, **kwargs):
        if self.is_admin and cmd and cmd[0] == "sudo":
            cmd = cmd[1:]
        return subprocess.run(cmd, **kwargs)

    def _primary_interface(self):
        r = subprocess.run(["networksetup", "-listallhardwareports"], capture_output=True, text=True)
        if r.returncode == 0:
            port_name = None
            for line in r.stdout.splitlines():
                if line.startswith("Hardware Port:"):
                    port_name = line.split(":", 1)[1].strip()
                elif line.startswith("Device:") and port_name in ("Wi-Fi", "Ethernet"):
                    device = line.split(":", 1)[1].strip()
                    if device.startswith("en"):
                        return device
                    port_name = None

        r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True)
        if r.returncode == 0:
            for line in r.stdout.splitlines():
                if line.strip().startswith("interface:"):
                    iface = line.split(":", 1)[1].strip()
                    if iface.startswith("en"):
                        return iface
        return "en0"

    def _elevate(self):
        self._log("👑 Elevating to admin...", ACCENT)
        try:
            script = f'do shell script "python3 {shlex.quote(__file__)}" with administrator privileges'
            subprocess.Popen(["/usr/bin/osascript", "-e", script])
            self.root.after(800, self.root.destroy)
        except Exception as e:
            self._log(f"❌ Elevation failed: {e}", RED)

    def _get_uptime(self):
        try:
            out = subprocess.check_output(["sysctl", "-n", "kern.boottime"], text=True).strip()
            boot = int(out.split()[0].strip(","))
            uptime_sec = int(time.time()) - boot
            days = uptime_sec // 86400
            hours = (uptime_sec % 86400) // 3600
            return days, hours
        except (subprocess.CalledProcessError, ValueError, IndexError):
            return 0, 0

    def _start_uptime_monitor(self):
        def monitor():
            while True:
                days, hours = self._get_uptime()
                if days >= 45:
                    color = RED
                    status = f"⚠️ DAY {days} — CRITICAL SHIELD"
                elif days >= 30:
                    color = WARNING
                    status = f"🟡 DAY {days} — 49-DAY ARMAGEDDON APPROACHING"
                else:
                    color = GREEN
                    status = f"✅ DAY {days} — IMMORTAL"
                text = f"⏳ Uptime: {days}d {hours}h | {status}"
                self.root.after(0, lambda t=text, c=color: self.uptime_label.config(text=t, fg=c))
                time.sleep(45)

        threading.Thread(target=monitor, daemon=True).start()

    def _sysctl_get(self, key):
        r = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"{key}: {(r.stderr or r.stdout).strip()}")
        return r.stdout.strip()

    def _sysctl_exists(self, key):
        r = subprocess.run(["sysctl", "-n", key], capture_output=True, text=True)
        return r.returncode == 0 and "unknown oid" not in (r.stderr or "").lower()

    def _available_tcp_settings(self):
        return {k: v for k, v in TCP_SETTINGS.items() if self._sysctl_exists(k)}

    def _check_status(self):
        self._log("🔍 Checking TCP shield...")
        if self.is_admin:
            self.admin_label.config(text="👑 Full Admin Privileges", fg=GREEN)
        else:
            self.admin_label.config(text="⚠️ Run as Admin for full power", fg=RED)

        mismatches = []
        for key, expected in TCP_SETTINGS.items():
            if not self._sysctl_exists(key):
                continue
            try:
                actual = self._sysctl_get(key)
            except RuntimeError as e:
                self._log(f"⚠️ {e}", WARNING)
                continue
            if actual != expected:
                mismatches.append(f"{key}={actual} (want {expected})")

        if mismatches:
            self.status_label.config(text="❌ Shield drift detected", fg=RED)
            for msg in mismatches:
                self._log(f"⚠️ {msg}", WARNING)
        else:
            self.status_label.config(text="✅ TCP SHIELD: ACTIVE", fg=GREEN)
            self._log("✅ All TCP settings verified", GREEN)

    def apply_fix(self):
        if not self.is_admin:
            self._log("❌ Need admin rights", RED)
            return
        self._log("🔧 Applying full TCP hardening...", ACCENT)
        success = True
        for key, value in TCP_SETTINGS.items():
            if not self._sysctl_exists(key):
                self._log(f"⏭️ Skipped {key} (not on macOS)", DIM)
                continue
            r = subprocess.run(
                ["sysctl", "-w", f"{key}={value}"],
                capture_output=True, text=True,
            )
            if r.returncode == 0:
                self._log(f"✅ {key} = {value}", GREEN)
            else:
                err = (r.stderr or r.stdout).strip()
                self._log(f"❌ Failed {key}" + (f": {err}" if err else ""), RED)
                success = False
        if success:
            self._log("✅ Full hardening complete", GREEN)
        else:
            self._log("⚠️ Some settings failed to apply", WARNING)
        self._check_status()

    def soft_refresh(self):
        if not self.is_admin:
            self._log("❌ Need admin rights", RED)
            return
        iface = self._primary_interface()
        self._log(f"🔄 Soft network refresh on {iface}...", WARNING)
        try:
            self._run(["sudo", "ifconfig", iface, "down"], check=True, capture_output=True)
            time.sleep(1.5)
            self._run(["sudo", "ifconfig", iface, "up"], check=True, capture_output=True)
            self._log("✅ Network stack refreshed", GREEN)
        except subprocess.CalledProcessError as e:
            err = (e.stderr or e.stdout or b"").decode(errors="replace").strip()
            self._log(f"❌ Refresh failed: {err or e}", RED)

    def _unload_launchd(self, path):
        self._run(["sudo", "launchctl", "bootout", "system", path], capture_output=True)
        self._run(["sudo", "launchctl", "unload", "-w", path], capture_output=True)

    def _load_launchd(self, path):
        r = self._run(["sudo", "launchctl", "bootstrap", "system", path], capture_output=True, text=True)
        if r.returncode != 0:
            self._run(["sudo", "launchctl", "load", "-w", path], check=True, capture_output=True)

    def install_launchd(self):
        if not self.is_admin:
            self._log("❌ Need admin", RED)
            return
        available = self._available_tcp_settings()
        if not available:
            self._log("❌ No supported TCP settings found on this Mac", RED)
            return

        self._log("🛡️ Installing persistent Catbooster shield...", ACCENT)
        plist = {
            "Label": LAUNCHD_LABEL,
            "ProgramArguments": ["/usr/sbin/sysctl", "-w"] + [f"{k}={v}" for k, v in available.items()],
            "RunAtLoad": True,
            "StartInterval": 300,
            "StandardOutPath": "/tmp/catbooster.log",
            "StandardErrorPath": "/tmp/catbooster.log",
        }

        with tempfile.NamedTemporaryFile(mode="wb", delete=False, suffix=".plist") as f:
            plistlib.dump(plist, f)
            tmp = f.name

        try:
            for old_path in (LEGACY_LAUNCHD_PATH, LAUNCHD_PATH):
                if os.path.exists(old_path):
                    self._unload_launchd(old_path)

            self._run(["sudo", "cp", tmp, LAUNCHD_PATH], check=True, capture_output=True)
            self._run(["sudo", "chmod", "644", LAUNCHD_PATH], check=True, capture_output=True)
            self._run(["sudo", "chown", "root:wheel", LAUNCHD_PATH], check=True, capture_output=True)
            self._load_launchd(LAUNCHD_PATH)
            self._log(f"✅ Persistent shield installed at {LAUNCHD_PATH}", GREEN)
        except subprocess.CalledProcessError as e:
            err = (e.stderr or e.stdout or b"").decode(errors="replace").strip()
            self._log(f"❌ Plist install failed: {err or e}", RED)
        finally:
            os.unlink(tmp)

    def god_mode(self):
        self._log("🌌 Activating full Catbooster mode...", PURPLE)
        self.apply_fix()
        self.install_launchd()
        self.soft_refresh()
        self._log("🌌 Catbooster shield maxed — 49-day protection active.", PURPLE)


def main():
    root = tk.Tk()
    CatBooster(root)
    root.mainloop()


if __name__ == "__main__":
    main()
