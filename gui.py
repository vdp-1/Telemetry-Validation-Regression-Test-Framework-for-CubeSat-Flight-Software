#!/usr/bin/env python3
"""
CubeSat Telemetry Monitoring GUI - Hardened single-file MVP

Key hardening applied:
 - GUI no longer creates or owns DB schema. If DB missing -> clear operator error.
 - Stable anomaly iids with anomaly_by_iid mapping (no fragile string parsing).
 - Charts default to latest-packet-centered window (avoids empty-chart confusion).
 - Use threading.Event() for run/pause control, and a cache_lock for shared caches.
 - Robust JSONL tail: detection of rotation/truncation and reopen with backoff.
 - DB read retries/backoff for transient locks.
 - Process spawn/monitoring retained (parser.py, ai.py, gen.py).
"""

import os
import sys
import sqlite3
import json
import threading
import queue
import time
import datetime
import subprocess
import csv
from pathlib import Path
from collections import deque

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ---------------- CONFIG ----------------
DB_PATH = Path("data") / "results.db"
JSONL_PATH = Path("data") / "ai_output.jsonl"
PARSER_SCRIPT = Path("parser.py")
AI_SCRIPT = Path("ai.py")
GEN_SCRIPT = Path("gen.py")

POLL_INTERVAL_S = 3.0
JSONL_POLL_INTERVAL_S = 1.0
MAX_PACKET_ROWS = 2000
CHART_WINDOW_SECONDS = 3600
CHART_METRICS = ["battery_mv", "batt_current_ma", "temp_centi", "power_mw"]

# ---------------- Concurrency primitives ----------------
_ui_queue = queue.Queue()
running_event = threading.Event()
running_event.set()
paused_event = threading.Event()   # when set => paused
cache_lock = threading.Lock()

# caches (thread-shared)
_packets_cache = deque(maxlen=MAX_PACKET_ROWS)
_anomalies_cache = []      # list of anomaly dicts
_anomaly_index = set()     # dedupe key set
anomaly_by_iid = {}        # iid(int) -> anomaly object
_next_anom_iid = 1

# process monitor state
_processes = {}
_process_log_queues = {}

# ---------------- Utility: UI logging ----------------
def ui_log(msg):
    ts = datetime.datetime.utcnow().isoformat(timespec='seconds') + "Z"
    _ui_queue.put(("log", f"[{ts}] {msg}"))

# ---------------- DB helpers (no schema creation!) ----------------
def open_db_connection_ro():
    """
    Open the DB in read-only mode if possible.
    Raises FileNotFoundError if DB does not exist.
    """
    if not DB_PATH.exists():
        raise FileNotFoundError(f"Database not found at {DB_PATH}. Please run parser.py to create it.")
    # open read-only connection using URI to avoid accidental creation.
    uri = f"file:{DB_PATH}?mode=ro"
    return sqlite3.connect(uri, uri=True, check_same_thread=False, timeout=5)

def _db_read_with_retries(query, params=(), retries=3, backoff=0.2):
    """
    Generic DB read wrapper with small retry/backoff to mitigate 'database is locked'.
    Returns fetched rows and column names.
    """
    last_exc = None
    for attempt in range(retries):
        try:
            conn = open_db_connection_ro()
            cur = conn.cursor()
            cur.execute(query, params)
            cols = [d[0] for d in cur.description] if cur.description else []
            rows = cur.fetchall()
            conn.close()
            return cols, rows
        except FileNotFoundError:
            raise
        except sqlite3.OperationalError as e:
            last_exc = e
            ui_log(f"DB read attempt {attempt+1}/{retries} failed: {e}. Retrying...")
            time.sleep(backoff * (1 << attempt))
            continue
        except Exception as e:
            last_exc = e
            ui_log(f"DB read unexpected error: {e}")
            break
    # if we get here, raise the last exception
    raise last_exc

def fetch_recent_packets(limit=500):
    """
    Returns list of packet dicts ordered by ts_ms ascending.
    """
    try:
        cols, rows = _db_read_with_retries(
            """
            SELECT packet_id, ts_ms, ts_iso, battery_mv, batt_current_ma, temp_centi, power_mw, soc_percent
            FROM packets
            ORDER BY ts_ms DESC
            LIMIT ?
            """,
            (limit,)
        )
        packets = [dict(zip(cols, r)) for r in rows]
        return list(reversed(packets))
    except FileNotFoundError:
        # DB missing: inform UI once
        ui_log(f"Database {DB_PATH} missing - polls will not run. Start parser.py to create DB.")
        return []
    except Exception as e:
        ui_log(f"fetch_recent_packets error: {e}")
        return []

def fetch_anomalies_from_db(limit=1000):
    """
    Returns list of anomaly dicts ordered by created_ms ascending (older->newer).
    """
    try:
        cols, rows = _db_read_with_retries(
            """
            SELECT packet_id, ts_ms, ts_iso, tag, severity, details, created_ms
            FROM ai_anomalies
            ORDER BY created_ms DESC
            LIMIT ?
            """,
            (limit,)
        )
        anomalies = []
        for r in rows:
            d = dict(zip(cols, r))
            try:
                if d.get("details") and isinstance(d["details"], str):
                    d["details_obj"] = json.loads(d["details"])
                else:
                    d["details_obj"] = d.get("details")
            except Exception:
                d["details_obj"] = d.get("details")
            anomalies.append(d)
        return list(reversed(anomalies))
    except FileNotFoundError:
        ui_log(f"Database {DB_PATH} missing - cannot fetch anomalies.")
        return []
    except Exception as e:
        ui_log(f"fetch_anomalies_from_db error: {e}")
        return []

# ---------------- Background threads ----------------
def db_polling_thread():
    """
    Poll DB for packets and anomalies. Put updates onto _ui_queue.
    """
    last_ts = None
    while running_event.is_set():
        if paused_event.is_set():
            time.sleep(POLL_INTERVAL_S)
            continue
        try:
            packets = fetch_recent_packets(limit=MAX_PACKET_ROWS)
            if packets:
                newest_ts = packets[-1].get("ts_ms")
            else:
                newest_ts = None
            # if changed, push
            if newest_ts != last_ts:
                last_ts = newest_ts
                _ui_queue.put(("packets_updated", packets))
            # sync anomalies from DB
            anomalies_db = fetch_anomalies_from_db(limit=1000)
            _ui_queue.put(("anomalies_db_sync", anomalies_db))
        except Exception as e:
            ui_log(f"db_polling_thread exception: {e}")
        time.sleep(POLL_INTERVAL_S)

def _stat_file(path):
    """
    Safe stat: return (inode, size, mtime) where inode may be None on some systems.
    """
    try:
        st = os.stat(path)
        ino = getattr(st, "st_ino", None)
        return (ino, st.st_size, st.st_mtime)
    except FileNotFoundError:
        return (None, 0, 0)
    except Exception:
        return (None, 0, 0)

def jsonl_tail_thread():
    """
    Tail JSONL file robustly. Detect rotation/truncation and reopen file.
    Push each parsed anomaly dict to UI queue.
    """
    path = JSONL_PATH
    last_stat = _stat_file(path)
    file_obj = None
    file_pos = 0
    reopen_backoff = 0.5
    while running_event.is_set():
        if paused_event.is_set():
            time.sleep(JSONL_POLL_INTERVAL_S)
            continue
        try:
            if file_obj is None:
                # attempt open (create if missing)
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    # open in read mode; if missing, create an empty file then reopen
                    if not path.exists():
                        path.write_text("")
                    file_obj = open(path, "r", encoding="utf-8")
                    # start at end for live tail
                    file_obj.seek(0, os.SEEK_END)
                    file_pos = file_obj.tell()
                    last_stat = _stat_file(path)
                    ui_log(f"JSONL tailer opened {path}")
                except Exception as e:
                    ui_log(f"Failed to open JSONL {path}: {e}. Retrying in {reopen_backoff}s")
                    time.sleep(reopen_backoff)
                    reopen_backoff = min(5.0, reopen_backoff * 2)
                    continue
            line = file_obj.readline()
            if not line:
                # detect truncation/rotation by checking file stat
                new_stat = _stat_file(path)
                if new_stat[0] != last_stat[0] or new_stat[1] < file_pos or new_stat[2] < last_stat[2]:
                    # file rotated/truncated: reopen
                    ui_log("Detected JSONL rotation/truncation — reopening tail file.")
                    try:
                        file_obj.close()
                    except Exception:
                        pass
                    file_obj = None
                    file_pos = 0
                    last_stat = new_stat
                    continue
                # no new line; sleep
                time.sleep(JSONL_POLL_INTERVAL_S)
                file_pos = file_obj.tell()
                continue
            file_pos = file_obj.tell()
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                _ui_queue.put(("jsonl_anomaly", obj))
            except Exception as e:
                ui_log(f"JSONL parse error: {e} | line: {line}")
        except Exception as e:
            ui_log(f"jsonl_tail_thread unexpected error: {e}")
            # close and retry after backoff
            try:
                if file_obj:
                    file_obj.close()
            except Exception:
                pass
            file_obj = None
            file_pos = 0
            time.sleep(1.0)

# ---------------- anomaly cache merge ----------------
def merge_anomaly_into_cache(anom):
    """
    Idempotent merge into _anomalies_cache with dedupe guard.
    """
    global _next_anom_iid
    try:
        pid = anom.get("packet_id")
        tag = anom.get("tag")
        created = anom.get("created_ms", anom.get("ts_ms", int(time.time()*1000)))
        key = (pid, tag, created)
        with cache_lock:
            if key in _anomaly_index:
                return False
            _anomaly_index.add(key)
            if isinstance(anom.get("details"), str):
                try:
                    anom["details_obj"] = json.loads(anom["details"])
                except Exception:
                    anom["details_obj"] = {"raw": anom.get("details")}
            else:
                anom["details_obj"] = anom.get("details")
            _anomalies_cache.append(anom)
            iid = f"anom_{_next_anom_iid}"
            anomaly_by_iid[iid] = anom
            _next_anom_iid += 1
            return True
    except Exception as e:
        ui_log(f"merge_anomaly_into_cache error: {e}")
        return False

# ---------------- process spawn & logs ----------------
def spawn_process(name, script_path):
    if not script_path.exists():
        ui_log(f"Cannot start {name}: script not found at {script_path}")
        return None
    # do not start if already running
    proc = _processes.get(name)
    if proc and proc.poll() is None:
        ui_log(f"{name} is already running (pid {proc.pid})")
        return proc
    try:
        proc = subprocess.Popen([sys.executable, str(script_path)],
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 text=True, bufsize=1)
        _processes[name] = proc
        q = queue.Queue()
        _process_log_queues[name] = q
        threading.Thread(target=_read_stream_to_queue, args=(proc.stdout, name, "stdout", q), daemon=True).start()
        threading.Thread(target=_read_stream_to_queue, args=(proc.stderr, name, "stderr", q), daemon=True).start()
        threading.Thread(target=_forward_process_logs, args=(name, q), daemon=True).start()
        ui_log(f"Started {name} (pid {proc.pid})")
        return proc
    except Exception as e:
        ui_log(f"Failed to start {name}: {e}")
        return None

def _read_stream_to_queue(stream, pname, which, q):
    try:
        for line in iter(stream.readline, ''):
            if not line:
                break
            q.put((which, line.rstrip()))
    except Exception as e:
        q.put(("stderr", f"stream read error: {e}"))

def _forward_process_logs(name, q):
    while running_event.is_set():
        try:
            which, line = q.get(timeout=1)
            ui_msg = f"[{name}][{which}] {line}"
            _ui_queue.put(("process_log", ui_msg))
        except queue.Empty:
            proc = _processes.get(name)
            if proc and proc.poll() is not None:
                ui_log(f"Process {name} exited with code {proc.returncode}")
                break
            continue

def stop_process(name):
    proc = _processes.get(name)
    if not proc:
        ui_log(f"No running process named {name}")
        return
    try:
        proc.terminate()
        ui_log(f"Terminated {name} (pid {proc.pid})")
    except Exception as e:
        ui_log(f"Failed to terminate {name}: {e}")

# ---------------- GUI ----------------
class TelemetryGUI:
    def __init__(self, master):
        self.master = master
        master.title("CubeSat Telemetry Monitor - Hardened MVP")
        self.style = ttk.Style(master)

        self.main_pane = ttk.Panedwindow(master, orient=tk.HORIZONTAL)
        self.main_pane.pack(fill=tk.BOTH, expand=True)

        left_frame = ttk.Frame(self.main_pane, padding=(4,4))
        self.main_pane.add(left_frame, weight=3)
        self._build_packet_table(left_frame)

        right_frame = ttk.Frame(self.main_pane, padding=(4,4))
        self.main_pane.add(right_frame, weight=4)
        self._build_right_panel(right_frame)

        bottom = ttk.Frame(master)
        bottom.pack(fill=tk.X)
        self._build_process_controls(bottom)

        self._build_menu(master)
        self.current_packet = None
        self.time_window_s = CHART_WINDOW_SECONDS

        # chart init
        self._init_charts()

        # wire UI queue processor
        self.master.after(200, self._process_ui_queue)

        # start background threads
        threading.Thread(target=db_polling_thread, daemon=True).start()
        threading.Thread(target=jsonl_tail_thread, daemon=True).start()

    def _build_menu(self, master):
        menubar = tk.Menu(master)
        master.config(menu=menubar)
        filem = tk.Menu(menubar, tearoff=False)
        filem.add_command(label="Export visible packets to CSV", command=self.export_packets_csv)
        filem.add_separator()
        filem.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=filem)
        menubar.add_command(label="Pause/Resume", command=self.toggle_pause)

    def _build_packet_table(self, parent):
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill=tk.X)
        ttk.Label(toolbar, text="Packets (recent)").pack(side=tk.LEFT)
        self.packet_search_var = tk.StringVar()
        ttk.Entry(toolbar, textvariable=self.packet_search_var, width=24).pack(side=tk.RIGHT, padx=4)
        ttk.Button(toolbar, text="Search", command=self.filter_packets).pack(side=tk.RIGHT)
        cols = ("packet_id", "ts_iso", "battery_mv", "batt_current_ma", "temp_centi", "power_mw", "soc_percent", "anomaly")
        self.packet_tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse", height=25)
        for c in cols:
            self.packet_tree.heading(c, text=c)
            self.packet_tree.column(c, width=100, anchor=tk.CENTER)
        self.packet_tree.pack(fill=tk.BOTH, expand=True)
        self.packet_tree.bind("<<TreeviewSelect>>", self.on_packet_select)

    def _build_right_panel(self, parent):
        top = ttk.Frame(parent)
        top.pack(fill=tk.BOTH, expand=True)
        top_toolbar = ttk.Frame(top)
        top_toolbar.pack(fill=tk.X)
        ttk.Label(top_toolbar, text="Anomalies").pack(side=tk.LEFT)
        self.severity_var = tk.StringVar(value="ALL")
        ttk.Combobox(top_toolbar, textvariable=self.severity_var, values=["ALL","major","critical"], width=8).pack(side=tk.LEFT, padx=4)
        ttk.Button(top_toolbar, text="Filter", command=self.filter_anomalies).pack(side=tk.LEFT)
        ttk.Button(top_toolbar, text="Export Anomalies CSV", command=self.export_anomalies_csv).pack(side=tk.RIGHT)
        self.anom_tree = ttk.Treeview(top, columns=("packet_id","ts_iso","tag","severity"), show="headings", height=8)
        for c in ("packet_id","ts_iso","tag","severity"):
            self.anom_tree.heading(c, text=c)
            self.anom_tree.column(c, width=100, anchor=tk.CENTER)
        self.anom_tree.pack(fill=tk.X)
        self.anom_tree.bind("<<TreeviewSelect>>", self.on_anomaly_select)

        mid = ttk.Panedwindow(parent, orient=tk.VERTICAL)
        mid.pack(fill=tk.BOTH, expand=True)

        detail_frame = ttk.Frame(mid)
        mid.add(detail_frame, weight=1)
        ttk.Label(detail_frame, text="Anomaly / Packet Detail (JSON)").pack(anchor=tk.W)
        self.detail_text = tk.Text(detail_frame, height=8)
        self.detail_text.pack(fill=tk.BOTH, expand=True)

        chart_frame = ttk.Frame(mid)
        mid.add(chart_frame, weight=2)
        chart_toolbar = ttk.Frame(chart_frame)
        chart_toolbar.pack(fill=tk.X)
        ttk.Label(chart_toolbar, text="Charts (select metrics)").pack(side=tk.LEFT)
        self.metric_vars = {}
        for m in CHART_METRICS:
            v = tk.BooleanVar(value=True)
            cb = ttk.Checkbutton(chart_toolbar, text=m, variable=v, command=self.update_charts)
            cb.pack(side=tk.LEFT, padx=2)
            self.metric_vars[m] = v
        ttk.Button(chart_toolbar, text="Set 1h window", command=lambda: self.set_time_window(3600)).pack(side=tk.RIGHT)
        ttk.Button(chart_toolbar, text="Set 10m window", command=lambda: self.set_time_window(600)).pack(side=tk.RIGHT)
        ttk.Button(chart_toolbar, text="Full history", command=self.set_full_history).pack(side=tk.RIGHT)
        ttk.Button(chart_toolbar, text="Refresh Charts", command=self.update_charts).pack(side=tk.RIGHT)
        self.chart_container = ttk.Frame(chart_frame)
        self.chart_container.pack(fill=tk.BOTH, expand=True)

    def _build_process_controls(self, parent):
        left = ttk.Frame(parent)
        left.pack(side=tk.LEFT)
        ttk.Button(left, text="Start parser.py", command=lambda: spawn_process("parser", PARSER_SCRIPT)).pack(side=tk.LEFT, padx=2)
        ttk.Button(left, text="Stop parser.py", command=lambda: stop_process("parser")).pack(side=tk.LEFT, padx=2)
        ttk.Button(left, text="Start ai.py", command=lambda: spawn_process("ai", AI_SCRIPT)).pack(side=tk.LEFT, padx=2)
        ttk.Button(left, text="Stop ai.py", command=lambda: stop_process("ai")).pack(side=tk.LEFT, padx=2)
        ttk.Button(left, text="Start gen.py", command=lambda: spawn_process("gen", GEN_SCRIPT)).pack(side=tk.LEFT, padx=2)
        ttk.Button(left, text="Stop gen.py", command=lambda: stop_process("gen")).pack(side=tk.LEFT, padx=2)
        ttk.Button(left, text="Pause UI updates", command=self.toggle_pause).pack(side=tk.LEFT, padx=6)
        right = ttk.Frame(parent)
        right.pack(side=tk.RIGHT, fill=tk.X, expand=True)
        ttk.Label(right, text="Process Logs").pack(anchor=tk.W)
        self.log_text = tk.Text(right, height=8)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def _init_charts(self):
        self.figure = Figure(figsize=(6,3))
        self.canvas = FigureCanvasTkAgg(self.figure, master=self.chart_container)
        self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    def _process_ui_queue(self):
        # run on Tk event loop
        while True:
            try:
                item = _ui_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._handle_ui_event(item)
            except Exception as e:
                print("UI event handling error:", e)
        self.master.after(200, self._process_ui_queue)

    def _handle_ui_event(self, item):
        typ = item[0]
        if typ == "log":
            _, text = item
            self._append_log(text)
        elif typ == "process_log":
            _, text = item
            self._append_log(text)
        elif typ == "packets_updated":
            _, packets = item
            self.update_packet_table(packets)
        elif typ == "anomalies_db_sync":
            _, anomalies = item
            count = 0
            for a in anomalies:
                if merge_anomaly_into_cache(a):
                    count += 1
            if count:
                self.refresh_anomaly_list()
        elif typ == "jsonl_anomaly":
            _, obj = item
            if merge_anomaly_into_cache(obj):
                self.refresh_anomaly_list()
        else:
            self._append_log(f"Unknown UI event: {item}")

    def _append_log(self, text):
        self.log_text.insert(tk.END, f"{text}\n")
        self.log_text.see(tk.END)

    # Packets
    def update_packet_table(self, packets):
        with cache_lock:
            _packets_cache.clear()
            for p in packets:
                _packets_cache.append(p)
        self.filter_packets()
        # update charts to show recent data if charts empty
        self.update_charts()

    def filter_packets(self):
        query = self.packet_search_var.get().strip().lower()
        self.packet_tree.delete(*self.packet_tree.get_children())
        with cache_lock:
            anomaly_packet_ids = {a.get("packet_id") for a in _anomalies_cache if a.get("packet_id") is not None}
            packets = list(_packets_cache)
        for p in packets:
            if query:
                if query not in json.dumps(p, default=str).lower():
                    continue
            an_flag = "YES" if p.get("packet_id") in anomaly_packet_ids else ""
            vals = (p.get("packet_id"), p.get("ts_iso"), p.get("battery_mv"), p.get("batt_current_ma"),
                    p.get("temp_centi"), p.get("power_mw"), p.get("soc_percent"), an_flag)
            iid = f"pkt_{p.get('packet_id')}"
            self.packet_tree.insert("", tk.END, iid=iid, values=vals)

    def on_packet_select(self, event):
        sel = self.packet_tree.selection()
        if not sel:
            return
        iid = sel[0]
        if iid.startswith("pkt_"):
            try:
                pid = int(iid.split("_",1)[1])
            except Exception:
                pid = None
            if pid is None:
                return
            with cache_lock:
                for p in _packets_cache:
                    if p.get("packet_id") == pid:
                        self.current_packet = p
                        break
                else:
                    self.current_packet = None
            self._show_packet_detail(self.current_packet)
            self.update_charts(center_packet=self.current_packet)

    def _show_packet_detail(self, packet):
        self.detail_text.delete("1.0", tk.END)
        if not packet:
            return
        self.detail_text.insert(tk.END, json.dumps(packet, indent=2, default=str))

    # Anomalies
    def refresh_anomaly_list(self):
        self.anom_tree.delete(*self.anom_tree.get_children())
        sev = self.severity_var.get()
        with cache_lock:
            items = list(anomaly_by_iid.items())
        for iid, a in items:
            if sev != "ALL" and a.get("severity") != sev:
                continue
            vals = (a.get("packet_id"), a.get("ts_iso"), a.get("tag"), a.get("severity"))
            self.anom_tree.insert("", tk.END, iid=iid, values=vals)

    def filter_anomalies(self):
        self.refresh_anomaly_list()

    def on_anomaly_select(self, event):
        sel = self.anom_tree.selection()
        if not sel:
            return
        iid = sel[0]
        with cache_lock:
            an = anomaly_by_iid.get(iid)
        if not an:
            return
        txt = json.dumps(an.get("details_obj", an), indent=2, default=str)
        self.detail_text.delete("1.0", tk.END)
        self.detail_text.insert(tk.END, txt)
        # highlight packet if in table
        pid = an.get("packet_id")
        if pid is not None:
            iid_pkt = f"pkt_{pid}"
            try:
                self.packet_tree.selection_set(iid_pkt)
                self.packet_tree.see(iid_pkt)
            except Exception:
                pass

    # Charts
    def set_time_window(self, seconds):
        self.time_window_s = seconds
        self.update_charts()

    def set_full_history(self):
        with cache_lock:
            if not _packets_cache:
                messagebox.showinfo("Full history", "No packets available to build full-history chart.")
                return
            ts_list = [p.get("ts_ms") for p in _packets_cache if p.get("ts_ms") is not None]
        if not ts_list:
            messagebox.showinfo("Full history", "No timestamped packets available.")
            return
        start = min(ts_list)
        end = max(ts_list)
        self.time_window_s = max(1, (end - start) / 1000.0)
        self.update_charts()

    def update_charts(self, center_packet=None):
        selected_metrics = [m for m, v in self.metric_vars.items() if v.get()]
        if not selected_metrics:
            selected_metrics = [CHART_METRICS[0]]
        self.figure.clf()
        n = len(selected_metrics)
        ax_map = {}
        for i, m in enumerate(selected_metrics, start=1):
            ax = self.figure.add_subplot(n, 1, i)
            ax.set_ylabel(m)
            ax_map[m] = ax

        # determine end_ts: prefer newest packet ts_ms if available
        with cache_lock:
            if center_packet:
                end_ts = int(center_packet.get("ts_ms") or time.time()*1000)
            elif _packets_cache:
                end_ts = int(_packets_cache[-1].get("ts_ms") or time.time()*1000)
            else:
                end_ts = int(time.time()*1000)
            start_ts = end_ts - int(self.time_window_s * 1000)
            times = [p for p in _packets_cache if p.get("ts_ms") is not None and start_ts <= p["ts_ms"] <= end_ts]

            # plot per metric
            for m, ax in ax_map.items():
                xs = [datetime.datetime.fromtimestamp(p["ts_ms"]/1000.0) for p in times if p.get(m) is not None]
                ys = [p.get(m) for p in times if p.get(m) is not None]
                if xs and ys:
                    ax.plot(xs, ys)
                    # overlay anomalies as 'x'
                    an_x = []
                    an_y = []
                    for a in _anomalies_cache:
                        pid = a.get("packet_id")
                        for p in times:
                            if p.get("packet_id") == pid and p.get(m) is not None:
                                an_x.append(datetime.datetime.fromtimestamp(p["ts_ms"]/1000.0))
                                an_y.append(p.get(m))
                    if an_x:
                        ax.scatter(an_x, an_y, marker='x')
                else:
                    ax.text(0.5, 0.5, "No data in window", transform=ax.transAxes, ha="center")
                ax.grid(True)
        try:
            self.figure.tight_layout()
            self.canvas.draw()
        except Exception:
            pass

    # CSV export
    def export_packets_csv(self):
        f = filedialog.asksaveasfilename(title="Save packets CSV", defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not f:
            return
        rows = []
        for iid in self.packet_tree.get_children():
            vals = self.packet_tree.item(iid, "values")
            rows.append(vals)
        if not rows:
            messagebox.showinfo("Export", "No packet rows to export.")
            return
        header = ("packet_id","ts_iso","battery_mv","batt_current_ma","temp_centi","power_mw","soc_percent","anomaly")
        try:
            with open(f, "w", newline='', encoding='utf-8') as fh:
                writer = csv.writer(fh)
                writer.writerow(header)
                writer.writerows(rows)
            messagebox.showinfo("Export", f"Exported {len(rows)} rows to {f}")
        except Exception as e:
            messagebox.showerror("Export", f"Failed to write CSV: {e}")

    def export_anomalies_csv(self):
        f = filedialog.asksaveasfilename(title="Save anomalies CSV", defaultextension=".csv", filetypes=[("CSV","*.csv")])
        if not f:
            return
        rows = []
        for iid in self.anom_tree.get_children():
            vals = self.anom_tree.item(iid, "values")
            rows.append(vals)
        header = ("packet_id","ts_iso","tag","severity")
        try:
            with open(f, "w", newline='', encoding='utf-8') as fh:
                writer = csv.writer(fh)
                writer.writerow(header)
                writer.writerows(rows)
            messagebox.showinfo("Export", f"Exported {len(rows)} anomaly rows to {f}")
        except Exception as e:
            messagebox.showerror("Export", f"Failed to write CSV: {e}")

    # pause control
    def toggle_pause(self):
        if paused_event.is_set():
            paused_event.clear()
            ui_log("UI updates resumed")
        else:
            paused_event.set()
            ui_log("UI updates paused")

    def _on_close(self):
        if not messagebox.askokcancel("Quit", "Exit Telemetry Monitor?"):
            return
        running_event.clear()
        # terminate subprocesses we launched
        for name in list(_processes.keys()):
            try:
                stop_process(name)
            except Exception:
                pass
        self.master.destroy()

# ---------------- main ----------------
def main():
    root = tk.Tk()
    app = TelemetryGUI(root)

    # On startup, verify DB presence. If missing, pop dialog
    if not DB_PATH.exists():
        # do not crash; inform operator with clear instruction
        message = (f"Database not found at {DB_PATH!s}.\n\n"
                   "This GUI will not create or modify the DB schema. "
                   "Please start parser.py to create the database (parser owns schema).\n\n"
                   "You can still start/monitor processes from the Process Controls.")
        messagebox.showwarning("Database missing", message)
        ui_log("Startup: database missing - parser.py must create DB before full functionality.")

    root.protocol("WM_DELETE_WINDOW", app._on_close)
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("Fatal error launching GUI:", e)

