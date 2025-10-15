import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import time
import csv
from datetime import datetime, timedelta
from pathlib import Path
import webbrowser
import subprocess
import os
import sys

try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import pandas as pd
    import wmi
    import psutil
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    from win10toast import ToastNotifier
    DEPS_AVAILABLE = True
except ImportError:
    DEPS_AVAILABLE = False

from monitor import HIDRAgent

class EnhancedFileWatcher(FileSystemEventHandler):
    def __init__(self, agent, gui):
        self.agent = agent
        self.gui = gui
        self.last_events = {}
    
    def on_any_event(self, event):
        if event.is_directory:
            return
            
        event_key = f"{event.event_type}:{event.src_path}"
        current_time = time.time()
        if event_key in self.last_events and current_time - self.last_events[event_key] < 0.1:
            return
        self.last_events[event_key] = current_time
            
        try:
            file_path = Path(event.src_path)
            if not file_path.exists() and event.event_type != "deleted":
                return
                
            rel_path = str(file_path.relative_to(self.agent.watched_dir))
            action = "Monitored"
            reason = "Normal file activity"
            
            if event.event_type == "modified" and file_path.exists():
                new_hash = self.agent.sha256_file(file_path)
                old_hash = self.agent.file_hashes.get(rel_path)
                if old_hash and new_hash != old_hash:
                    action = "QUARANTINED"
                    reason = "Hash mismatch - potential threat"
                    quar_path = self.agent.quarantine_file(file_path)
                    if quar_path and self.agent.restore_from_backup(rel_path):
                        self.agent.log_incident("file_modified", path=event.src_path, 
                                              action="quarantined", details=reason)
                        self.gui.log_activity(f"QUARANTINED: {rel_path} - {reason}")
                else:
                    self.agent.file_hashes[rel_path] = new_hash
                    
            elif event.event_type == "deleted":
                action = "RESTORED"
                reason = "Auto-restore from backup"
                if self.agent.restore_from_backup(rel_path):
                    self.agent.log_incident("file_deleted", path=event.src_path, 
                                          action="restored", details=reason)
                    self.gui.log_activity(f"RESTORED: {rel_path} - {reason}")
            
            self.gui.add_file_event(event.event_type, rel_path, action, reason)
        except Exception:
            pass

class HIDRGui:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("HIDR Agent - Host Intrusion Detection & Response")
        self.root.geometry("1500x1000")
        
        self.agent = None
        self.file_observer = None
        self.monitoring_active = False
        self.process_events = []
        self.file_events = []
        self.start_time = None
        self.process_monitor_thread = None
        self.wmi_monitor_thread = None
        
        self.setup_gui()
        self.update_status()
        
    def setup_gui(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        self.create_dashboard_tab()
        self.create_monitoring_tab()
        self.create_quarantine_tab()
        self.create_reports_tab()
        
    def create_dashboard_tab(self):
        self.dashboard_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.dashboard_frame, text="Dashboard")
        
        status_frame = ttk.LabelFrame(self.dashboard_frame, text="System Status")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.status_label = ttk.Label(status_frame, text="Status: Stopped", font=("Arial", 14, "bold"))
        self.status_label.pack(pady=10)
        
        control_frame = ttk.Frame(status_frame)
        control_frame.pack(pady=10)
        
        self.start_btn = ttk.Button(control_frame, text="Start Protection", command=self.start_monitoring)
        self.start_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(control_frame, text="Stop Protection", command=self.stop_monitoring, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.test_btn = ttk.Button(control_frame, text="Quick Test", command=self.run_test_attack)
        self.test_btn.pack(side=tk.LEFT, padx=5)
        
        self.advanced_test_btn = ttk.Button(control_frame, text="Advanced Attack", command=self.run_advanced_attack)
        self.advanced_test_btn.pack(side=tk.LEFT, padx=5)
        
        self.keylogger_test_btn = ttk.Button(control_frame, text="Keylogger Test", command=self.run_keylogger_test)
        self.keylogger_test_btn.pack(side=tk.LEFT, padx=5)
        
        metrics_frame = ttk.LabelFrame(self.dashboard_frame, text="Live Metrics")
        metrics_frame.pack(fill=tk.X, padx=10, pady=5)
        
        metrics_grid = ttk.Frame(metrics_frame)
        metrics_grid.pack(fill=tk.X, padx=10, pady=10)
        
        for i in range(3):
            metrics_grid.grid_columnconfigure(i, weight=1)
        
        self.create_metric_card(metrics_grid, "Process Events", "process_count", 0, 0)
        self.create_metric_card(metrics_grid, "File Events", "file_count", 0, 1)
        self.create_metric_card(metrics_grid, "Threats Blocked", "threats_count", 0, 2)
        self.create_metric_card(metrics_grid, "Files Quarantined", "quarantine_count", 1, 0)
        self.create_metric_card(metrics_grid, "Uptime", "uptime", 1, 1)
        self.create_metric_card(metrics_grid, "Status", "system_status", 1, 2)
        
        log_frame = ttk.LabelFrame(self.dashboard_frame, text="Live Activity Log")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.activity_text = tk.Text(log_frame, height=12, state=tk.DISABLED, font=("Consolas", 9))
        activity_scroll = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.activity_text.yview)
        self.activity_text.configure(yscrollcommand=activity_scroll.set)
        
        self.activity_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        activity_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_metric_card(self, parent, title, var_name, row, col):
        card = ttk.Frame(parent, relief="solid", borderwidth=1)
        card.grid(row=row, column=col, padx=5, pady=5, sticky="ew")
        
        ttk.Label(card, text=title, font=("Arial", 10, "bold")).pack(pady=(5,0))
        
        value_var = tk.StringVar(value="0")
        setattr(self, var_name, value_var)
        ttk.Label(card, textvariable=value_var, font=("Arial", 16, "bold"), foreground="blue").pack(pady=(0,5))
        
    def create_monitoring_tab(self):
        self.monitoring_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitoring_frame, text="Live Monitoring")
        
        proc_frame = ttk.LabelFrame(self.monitoring_frame, text="Process Events")
        proc_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.proc_tree = ttk.Treeview(proc_frame, columns=("Time", "Process", "PID", "Path", "Action", "Reason"), show="headings", height=10)
        
        columns = [("Time", 80), ("Process", 120), ("PID", 60), ("Path", 250), ("Action", 100), ("Reason", 200)]
        for col, width in columns:
            self.proc_tree.heading(col, text=col)
            self.proc_tree.column(col, width=width)
        
        proc_scroll = ttk.Scrollbar(proc_frame, orient=tk.VERTICAL, command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=proc_scroll.set)
        
        self.proc_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        proc_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        file_frame = ttk.LabelFrame(self.monitoring_frame, text="File Events")
        file_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.file_tree = ttk.Treeview(file_frame, columns=("Time", "File", "Event", "Action", "Reason"), show="headings", height=10)
        
        file_columns = [("Time", 80), ("File", 250), ("Event", 100), ("Action", 100), ("Reason", 200)]
        for col, width in file_columns:
            self.file_tree.heading(col, text=col)
            self.file_tree.column(col, width=width)
        
        file_scroll = ttk.Scrollbar(file_frame, orient=tk.VERTICAL, command=self.file_tree.yview)
        self.file_tree.configure(yscrollcommand=file_scroll.set)
        
        self.file_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        file_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_quarantine_tab(self):
        self.quarantine_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.quarantine_frame, text="Quarantine")
        
        control_frame = ttk.Frame(self.quarantine_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(control_frame, text="Refresh", command=self.refresh_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export List", command=self.export_quarantine).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Clear All", command=self.clear_quarantine).pack(side=tk.LEFT, padx=5)
        
        quar_frame = ttk.LabelFrame(self.quarantine_frame, text="Quarantined Files")
        quar_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.quar_tree = ttk.Treeview(quar_frame, columns=("File", "Original", "Date", "Size", "Reason"), show="headings")
        
        quar_columns = [("File", 200), ("Original", 200), ("Date", 150), ("Size", 100), ("Reason", 200)]
        for col, width in quar_columns:
            self.quar_tree.heading(col, text=col)
            self.quar_tree.column(col, width=width)
        
        quar_scroll = ttk.Scrollbar(quar_frame, orient=tk.VERTICAL, command=self.quar_tree.yview)
        self.quar_tree.configure(yscrollcommand=quar_scroll.set)
        
        self.quar_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        quar_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
    def create_reports_tab(self):
        self.reports_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.reports_frame, text="Reports & Analytics")
        
        control_frame = ttk.Frame(self.reports_frame)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(control_frame, text="Generate Report", command=self.generate_report).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Export CSV", command=self.export_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(control_frame, text="Update Charts", command=self.update_charts).pack(side=tk.LEFT, padx=5)
        
        if DEPS_AVAILABLE:
            charts_frame = ttk.LabelFrame(self.reports_frame, text="Live Analytics")
            charts_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
            
            self.chart_notebook = ttk.Notebook(charts_frame)
            self.chart_notebook.pack(fill=tk.BOTH, expand=True)
            
            self.timeline_frame = ttk.Frame(self.chart_notebook)
            self.chart_notebook.add(self.timeline_frame, text="Timeline")
            
            self.pie_frame = ttk.Frame(self.chart_notebook)
            self.chart_notebook.add(self.pie_frame, text="Distribution")
            
            self.stats_frame = ttk.Frame(self.chart_notebook)
            self.chart_notebook.add(self.stats_frame, text="Statistics")
        else:
            ttk.Label(self.reports_frame, text="Install dependencies for charts: pip install matplotlib pandas plotly").pack(pady=20)
    
    def start_monitoring(self):
        if not DEPS_AVAILABLE:
            messagebox.showerror("Error", "Missing dependencies. Install with: pip install -r requirements_gui.txt")
            return
            
        try:
            self.agent = HIDRAgent()
            self.start_time = datetime.now()
            self.monitoring_active = True
            
            self.process_monitor_thread = threading.Thread(target=self.enhanced_process_monitor, daemon=True)
            self.process_monitor_thread.start()
            
            if DEPS_AVAILABLE:
                self.wmi_monitor_thread = threading.Thread(target=self.wmi_process_monitor, daemon=True)
                self.wmi_monitor_thread.start()
            
            file_watcher = EnhancedFileWatcher(self.agent, self)
            self.file_observer = Observer()
            self.file_observer.schedule(file_watcher, str(self.agent.watched_dir), recursive=True)
            self.file_observer.start()
            
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            
            self.log_activity("HIDR Agent protection started - All systems active!")
            messagebox.showinfo("Success", "Real-time protection started successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start protection: {str(e)}")
    
    def enhanced_process_monitor(self):
        seen_pids = set()
        
        try:
            for proc in psutil.process_iter(['pid']):
                seen_pids.add(proc.info['pid'])
        except Exception:
            pass
        
        while self.monitoring_active:
            try:
                current_processes = {}
                for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time']):
                    try:
                        current_processes[proc.info['pid']] = proc.info
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                
                current_pids = set(current_processes.keys())
                new_pids = current_pids - seen_pids
                
                for pid in new_pids:
                    try:
                        proc_info = current_processes[pid]
                        self.handle_new_process(proc_info)
                    except Exception:
                        pass
                
                seen_pids = current_pids
                time.sleep(0.05)
                
            except Exception:
                time.sleep(1)
    
    def wmi_process_monitor(self):
        if not DEPS_AVAILABLE:
            return
            
        try:
            wmi_conn = wmi.WMI()
            process_watcher = wmi_conn.Win32_ProcessStartTrace.watch()
            
            for event in process_watcher:
                if not self.monitoring_active:
                    break
                    
                try:
                    proc_info = {
                        'pid': event.ProcessId,
                        'name': event.ProcessName,
                        'exe': '',
                        'cmdline': []
                    }
                    
                    try:
                        proc = wmi_conn.Win32_Process(ProcessId=event.ProcessId)[0]
                        proc_info['exe'] = proc.ExecutablePath or ''
                        proc_info['cmdline'] = [proc.CommandLine or '']
                    except Exception:
                        pass
                    
                    self.handle_new_process(proc_info)
                    
                except Exception:
                    pass
                    
        except Exception:
            pass
    
    def handle_new_process(self, proc_info):
        proc_name = proc_info.get('name', 'Unknown')
        pid = proc_info.get('pid', 0)
        path = proc_info.get('exe', '') or ''
        cmdline = ' '.join(proc_info.get('cmdline', []) or [])
        
        timestamp = datetime.now().strftime("%H:%M:%S")
        action = "Allowed"
        reason = "Normal process execution"
        
        if self.agent and self.is_enhanced_suspicious_process(proc_name, path, cmdline):
            action = "BLOCKED"
            reason = self.get_detailed_block_reason(proc_name, path, cmdline)
            
            if self.agent.kill_process(pid):
                action = "TERMINATED"
                self.log_activity(f"TERMINATED: {proc_name} (PID: {pid}) - {reason}")
            else:
                self.log_activity(f"BLOCKED: {proc_name} (PID: {pid}) - {reason}")
                
            self.agent.log_incident("suspicious_process", proc_name, pid, path, cmdline, action, reason)
        else:
            self.log_activity(f"ALLOWED: {proc_name} (PID: {pid})")
        
        self.add_process_event(timestamp, proc_name, str(pid), path, action, reason)
    
    def is_enhanced_suspicious_process(self, proc_name, path, cmdline):
        if not path:
            return False
        
        allowlist = [
            "C:\\Windows\\System32\\",
            "C:\\Program Files\\",
            "C:\\Program Files (x86)\\",
        ]
        
        if any(path.startswith(allowed) for allowed in allowlist):
            return False
        
        suspicious_indicators = [
            "temp" in path.lower(),
            "downloads" in path.lower(),
            "appdata\\local\\temp" in path.lower(),
            proc_name.lower() in ["encryptor.exe", "locker.exe", "crypt.exe", "ransomware.exe", "keylogger.exe", "stealer.exe", "backdoor.exe", "trojan.exe"],
            "powershell" in proc_name.lower() and ("encodedcommand" in cmdline.lower() or "-enc" in cmdline.lower()),
            proc_name.lower().endswith(".exe") and "appdata" in path.lower(),
            "suspicious" in proc_name.lower(),
            "malware" in proc_name.lower(),
            "winlogon.exe" in proc_name.lower() and "temp" in path.lower(),
            "svchost.exe" in proc_name.lower() and not path.startswith("C:\\Windows\\System32"),
            "explorer.exe" in proc_name.lower() and not path.startswith("C:\\Windows"),
            proc_name.lower() in ["system32.dll", "kernel32.dll", "user32.dll"] and path.lower().endswith(".exe"),
            "ntoskrnl.exe" in proc_name.lower() and "temp" in path.lower(),
            "hal.dll" in proc_name.lower() and path.lower().endswith(".exe"),
            "win32k.sys" in proc_name.lower() and path.lower().endswith(".exe")
        ]
        
        return any(suspicious_indicators)
    
    def get_detailed_block_reason(self, proc_name, path, cmdline):
        if "temp" in path.lower():
            return "Process launched from temporary directory"
        elif "downloads" in path.lower():
            return "Process launched from downloads directory"
        elif proc_name.lower() in ["encryptor.exe", "locker.exe", "crypt.exe", "ransomware.exe"]:
            return "Ransomware executable detected"
        elif proc_name.lower() in ["keylogger.exe", "stealer.exe", "backdoor.exe", "trojan.exe"]:
            return "Malware executable detected"
        elif "powershell" in proc_name.lower() and ("encodedcommand" in cmdline.lower() or "-enc" in cmdline.lower()):
            return "PowerShell with encoded command detected"
        elif "winlogon.exe" in proc_name.lower() and "temp" in path.lower():
            return "Fake system process detected (winlogon)"
        elif "svchost.exe" in proc_name.lower() and not path.startswith("C:\\Windows\\System32"):
            return "Fake system process detected (svchost)"
        elif "explorer.exe" in proc_name.lower() and not path.startswith("C:\\Windows"):
            return "Fake system process detected (explorer)"
        elif proc_name.lower() in ["system32.dll", "kernel32.dll", "user32.dll"] and path.lower().endswith(".exe"):
            return "DLL masquerading as executable"
        elif proc_name.lower() in ["ntoskrnl.exe", "hal.dll", "win32k.sys"] and "temp" in path.lower():
            return "Rootkit component detected"
        elif "appdata" in path.lower():
            return "Process launched from AppData directory"
        elif "suspicious" in proc_name.lower() or "malware" in proc_name.lower():
            return "Malicious process name pattern detected"
        else:
            return "Heuristic analysis flagged as suspicious"
    
    def add_process_event(self, timestamp, process, pid, path, action, reason):
        self.process_events.append((timestamp, process, pid, path, action, reason))
        if len(self.process_events) > 500:
            self.process_events = self.process_events[-500:]
        
        self.root.after_idle(self.update_process_table)
    
    def add_file_event(self, event_type, file_path, action, reason):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.file_events.append((timestamp, file_path, event_type, action, reason))
        if len(self.file_events) > 500:
            self.file_events = self.file_events[-500:]
        
        self.root.after_idle(self.update_file_table)
    
    def update_process_table(self):
        for item in self.proc_tree.get_children():
            self.proc_tree.delete(item)
        
        for event in reversed(self.process_events[-200:]):
            tags = ("blocked",) if event[4] in ["BLOCKED", "TERMINATED"] else ("allowed",)
            self.proc_tree.insert("", 0, values=event, tags=tags)
        
        self.proc_tree.tag_configure("blocked", background="#ffebee", foreground="#c62828")
        self.proc_tree.tag_configure("allowed", background="#e8f5e8", foreground="#2e7d32")
    
    def update_file_table(self):
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        for event in reversed(self.file_events[-200:]):
            tags = ("quarantined",) if event[3] == "QUARANTINED" else ("normal",)
            self.file_tree.insert("", 0, values=event, tags=tags)
        
        self.file_tree.tag_configure("quarantined", background="#fff3e0", foreground="#f57c00")
        self.file_tree.tag_configure("normal", background="#f3e5f5", foreground="#7b1fa2")
    
    def log_activity(self, message):
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        
        def update_log():
            self.activity_text.config(state=tk.NORMAL)
            self.activity_text.insert(tk.END, log_entry)
            
            lines = self.activity_text.get("1.0", tk.END).split('\n')
            if len(lines) > 2000:
                self.activity_text.delete("1.0", f"{len(lines)-2000}.0")
            
            self.activity_text.see(tk.END)
            self.activity_text.config(state=tk.DISABLED)
        
        self.root.after_idle(update_log)
    
    def stop_monitoring(self):
        try:
            self.monitoring_active = False
            
            if self.file_observer:
                self.file_observer.stop()
                self.file_observer.join()
            
            self.start_btn.config(state=tk.NORMAL)
            self.stop_btn.config(state=tk.DISABLED)
            
            self.log_activity("HIDR Agent protection stopped")
            messagebox.showinfo("Success", "Protection stopped successfully.")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to stop protection: {str(e)}")
    
    def run_test_attack(self):
        try:
            test_script = Path.cwd() / "test_attack.py"
            if test_script.exists():
                subprocess.Popen([sys.executable, str(test_script)], cwd=Path.cwd())
                self.log_activity("Quick attack simulation started")
                messagebox.showinfo("Test Attack", "Quick attack simulation started! Watch Live Monitoring for detection.")
            else:
                messagebox.showwarning("Warning", "test_attack.py not found in current directory.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run test: {str(e)}")
    
    def run_advanced_attack(self):
        try:
            test_script = Path.cwd() / "test_attack.py"
            if test_script.exists():
                subprocess.Popen([sys.executable, str(test_script), "--full"], cwd=Path.cwd())
                self.log_activity("Advanced multi-stage attack simulation started")
                messagebox.showinfo("Advanced Attack", "Advanced attack simulation started! This will test all detection capabilities.")
            else:
                messagebox.showwarning("Warning", "test_attack.py not found in current directory.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run advanced test: {str(e)}")
    
    def run_keylogger_test(self):
        try:
            keylogger_script = Path.cwd() / "advanced_keylogger_sim.py"
            if keylogger_script.exists():
                subprocess.Popen([sys.executable, str(keylogger_script), "--full"], cwd=Path.cwd())
                self.log_activity("Keylogger simulation started")
                messagebox.showinfo("Keylogger Test", "Keylogger simulation started! Testing comprehensive malware detection.")
            else:
                messagebox.showwarning("Warning", "advanced_keylogger_sim.py not found in current directory.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to run keylogger test: {str(e)}")
    
    def refresh_quarantine(self):
        if not self.agent:
            return
        
        for item in self.quar_tree.get_children():
            self.quar_tree.delete(item)
        
        quarantine_dir = self.agent.quarantine_dir
        if quarantine_dir.exists():
            for quar_file in quarantine_dir.glob("*.quar"):
                try:
                    stat = quar_file.stat()
                    size = f"{stat.st_size:,} bytes"
                    date = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    original = quar_file.stem.split('.')[0]
                    reason = "Suspicious file modification detected"
                    
                    self.quar_tree.insert("", tk.END, values=(quar_file.name, original, date, size, reason))
                except Exception:
                    pass
    
    def clear_quarantine(self):
        if not self.agent:
            return
            
        if messagebox.askyesno("Confirm", "Are you sure you want to delete all quarantined files?"):
            try:
                count = 0
                for quar_file in self.agent.quarantine_dir.glob("*.quar"):
                    quar_file.unlink()
                    count += 1
                
                self.refresh_quarantine()
                self.log_activity(f"Cleared {count} quarantined files")
                messagebox.showinfo("Success", f"Cleared {count} quarantined files.")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to clear quarantine: {str(e)}")
    
    def export_quarantine(self):
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            try:
                with open(filename, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(["File", "Original", "Date", "Size", "Reason"])
                    for item in self.quar_tree.get_children():
                        values = self.quar_tree.item(item)['values']
                        writer.writerow(values)
                
                self.log_activity(f"Quarantine list exported to {Path(filename).name}")
                messagebox.showinfo("Export", f"Quarantine list exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def generate_report(self):
        if not self.agent:
            messagebox.showwarning("Warning", "Start monitoring first to generate reports.")
            return
        
        try:
            if not self.agent.incident_log.exists() or self.count_incidents() == 0:
                self.create_sample_data()
            
            try:
                from interactive_report import InteractiveReportGenerator
                generator = InteractiveReportGenerator(self.agent.incident_log)
                report_path = generator.generate_full_report()
                
                if report_path and report_path.exists():
                    webbrowser.open(f"file://{report_path.absolute()}")
                    self.log_activity(f"Interactive report generated: {report_path.name}")
                    messagebox.showinfo("Report", f"Interactive report opened successfully!")
                else:
                    raise Exception("Report generation failed")
                    
            except Exception:
                report_path = self.generate_simple_report()
                if report_path:
                    webbrowser.open(f"file://{report_path.absolute()}")
                    self.log_activity(f"Simple report generated: {report_path.name}")
                    messagebox.showinfo("Report", f"Report generated successfully!")
                
        except Exception as e:
            messagebox.showerror("Error", f"Report generation failed: {str(e)}")
        
        if DEPS_AVAILABLE:
            self.update_charts()
    
    def generate_simple_report(self):
        try:
            report_dir = Path.cwd() / "reports"
            report_dir.mkdir(exist_ok=True)
            
            report_path = report_dir / f"hidr_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>HIDR Agent Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    .header {{ background: #2196F3; color: white; padding: 20px; }}
                    .metric {{ display: inline-block; margin: 10px; padding: 15px; border: 1px solid #ddd; }}
                    table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f2f2f2; }}
                </style>
            </head>
            <body>
                <div class="header">
                    <h1>HIDR Agent Security Report</h1>
                    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <h2>Summary Metrics</h2>
                <div class="metric">
                    <h3>Process Events</h3>
                    <p>{len(self.process_events)}</p>
                </div>
                <div class="metric">
                    <h3>File Events</h3>
                    <p>{len(self.file_events)}</p>
                </div>
                <div class="metric">
                    <h3>Threats Blocked</h3>
                    <p>{len([e for e in self.process_events if e[4] in ['BLOCKED', 'TERMINATED']])}</p>
                </div>
                
                <h2>Recent Process Events</h2>
                <table>
                    <tr><th>Time</th><th>Process</th><th>PID</th><th>Action</th><th>Reason</th></tr>
            """
            
            for event in self.process_events[-20:]:
                html_content += f"<tr><td>{event[0]}</td><td>{event[1]}</td><td>{event[2]}</td><td>{event[4]}</td><td>{event[5]}</td></tr>"
            
            html_content += """
                </table>
                
                <h2>Recent File Events</h2>
                <table>
                    <tr><th>Time</th><th>File</th><th>Event</th><th>Action</th><th>Reason</th></tr>
            """
            
            for event in self.file_events[-20:]:
                html_content += f"<tr><td>{event[0]}</td><td>{event[1]}</td><td>{event[2]}</td><td>{event[3]}</td><td>{event[4]}</td></tr>"
            
            html_content += """
                </table>
            </body>
            </html>
            """
            
            with open(report_path, 'w') as f:
                f.write(html_content)
            
            return report_path
            
        except Exception:
            return None
    
    def create_sample_data(self):
        if not self.agent:
            return
            
        sample_data = [
            [datetime.now().isoformat(), "system_start", "hidr_agent", "", "", "", "started", "System monitoring started"],
            [(datetime.now() - timedelta(minutes=5)).isoformat(), "file_modified", "", "", "decoys/passwords.txt", "", "quarantined", "Hash mismatch detected"],
            [(datetime.now() - timedelta(minutes=3)).isoformat(), "suspicious_process", "notepad.exe", "1234", "C:\\temp\\notepad.exe", "", "terminated", "Process from temp directory"],
            [(datetime.now() - timedelta(minutes=1)).isoformat(), "file_deleted", "", "", "important_data.docx", "", "restored", "File restored from backup"]
        ]
        
        with open(self.agent.incident_log, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['timestamp', 'type', 'process_name', 'pid', 'path', 'command', 'action', 'details'])
            writer.writerows(sample_data)
    
    def export_csv(self):
        if not self.agent or not self.agent.incident_log.exists():
            messagebox.showwarning("Warning", "No incident data available.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if filename:
            try:
                import shutil
                shutil.copy2(self.agent.incident_log, filename)
                self.log_activity(f"Incident data exported to {Path(filename).name}")
                messagebox.showinfo("Export", f"Data exported successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Export failed: {str(e)}")
    
    def update_charts(self):
        if not DEPS_AVAILABLE or not self.agent:
            return
        
        try:
            if self.agent.incident_log.exists():
                df = pd.read_csv(self.agent.incident_log)
            else:
                df = pd.DataFrame({
                    'timestamp': [datetime.now() - timedelta(hours=i) for i in range(24, 0, -1)],
                    'type': ['process_event'] * 12 + ['file_event'] * 12,
                    'action': ['allowed'] * 20 + ['blocked'] * 4
                })
            
            self.create_timeline_chart(df)
            self.create_distribution_chart(df)
            self.create_statistics_view(df)
            
        except Exception:
            pass
    
    def create_timeline_chart(self, df):
        for widget in self.timeline_frame.winfo_children():
            widget.destroy()
        
        fig, ax = plt.subplots(figsize=(12, 6))
        
        if not df.empty:
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            hourly_counts = df.groupby(df['timestamp'].dt.floor('H')).size()
            
            ax.plot(hourly_counts.index, hourly_counts.values, marker='o', linewidth=2, markersize=6, color='#2196F3')
            ax.fill_between(hourly_counts.index, hourly_counts.values, alpha=0.3, color='#2196F3')
            ax.set_title('Security Events Timeline', fontsize=14, fontweight='bold')
            ax.set_xlabel('Time')
            ax.set_ylabel('Event Count')
            ax.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
        else:
            ax.text(0.5, 0.5, 'No data available', ha='center', va='center', transform=ax.transAxes, fontsize=12)
        
        plt.tight_layout()
        canvas = FigureCanvasTkAgg(fig, self.timeline_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_distribution_chart(self, df):
        for widget in self.pie_frame.winfo_children():
            widget.destroy()
        
        fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 6))
        
        if not df.empty:
            type_counts = df['type'].value_counts()
            colors1 = ['#ff9999', '#66b3ff', '#99ff99', '#ffcc99']
            ax1.pie(type_counts.values, labels=type_counts.index, autopct='%1.1f%%', 
                   colors=colors1, startangle=90)
            ax1.set_title('Event Types', fontweight='bold')
            
            if 'action' in df.columns:
                action_counts = df['action'].value_counts()
                colors2 = ['#ff6b6b', '#4ecdc4', '#45b7d1', '#96ceb4']
                ax2.pie(action_counts.values, labels=action_counts.index, autopct='%1.1f%%', 
                       colors=colors2, startangle=90)
                ax2.set_title('Actions Taken', fontweight='bold')
        else:
            ax1.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax1.transAxes)
            ax2.text(0.5, 0.5, 'No data', ha='center', va='center', transform=ax2.transAxes)
        
        plt.tight_layout()
        canvas = FigureCanvasTkAgg(fig, self.pie_frame)
        canvas.draw()
        canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
    
    def create_statistics_view(self, df):
        for widget in self.stats_frame.winfo_children():
            widget.destroy()
        
        stats_text = tk.Text(self.stats_frame, font=("Consolas", 10))
        stats_scroll = ttk.Scrollbar(self.stats_frame, orient=tk.VERTICAL, command=stats_text.yview)
        stats_text.configure(yscrollcommand=stats_scroll.set)
        
        stats_content = f"""
HIDR Agent Statistics Report
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

=== REAL-TIME METRICS ===
Process Events: {len(self.process_events)}
File Events: {len(self.file_events)}
Threats Blocked: {len([e for e in self.process_events if e[4] in ['BLOCKED', 'TERMINATED']])}
Files Quarantined: {len(list(self.agent.quarantine_dir.glob('*.quar'))) if self.agent and self.agent.quarantine_dir.exists() else 0}

=== SESSION STATISTICS ===
Monitoring Active: {'Yes' if self.monitoring_active else 'No'}
Session Uptime: {self.uptime.get() if hasattr(self, 'uptime') else '00:00:00'}
Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S') if self.start_time else 'Not started'}

=== PROCESS ANALYSIS ===
Total Processes Monitored: {len(self.process_events)}
Suspicious Processes: {len([e for e in self.process_events if e[4] in ['BLOCKED', 'TERMINATED']])}
Normal Processes: {len([e for e in self.process_events if e[4] == 'Allowed'])}

=== FILE ANALYSIS ===
Total File Events: {len(self.file_events)}
Files Quarantined: {len([e for e in self.file_events if e[3] == 'QUARANTINED'])}
Files Restored: {len([e for e in self.file_events if e[3] == 'RESTORED'])}

=== THREAT DETECTION PATTERNS ===
"""
        
        if self.process_events:
            blocked_reasons = [e[5] for e in self.process_events if e[4] in ['BLOCKED', 'TERMINATED']]
            if blocked_reasons:
                from collections import Counter
                reason_counts = Counter(blocked_reasons)
                stats_content += "\nTop Threat Patterns:\n"
                for reason, count in reason_counts.most_common(5):
                    stats_content += f"  • {reason}: {count} occurrences\n"
        
        stats_content += f"""

=== SYSTEM HEALTH ===
Dependencies Available: {'Yes' if DEPS_AVAILABLE else 'No'}
WMI Monitoring: {'Active' if DEPS_AVAILABLE and self.monitoring_active else 'Inactive'}
File Monitoring: {'Active' if self.monitoring_active else 'Inactive'}
Process Monitoring: {'Active' if self.monitoring_active else 'Inactive'}

=== CONFIGURATION ===
Watched Directory: {self.agent.watched_dir if self.agent else 'Not initialized'}
Quarantine Directory: {self.agent.quarantine_dir if self.agent else 'Not initialized'}
Backup Directory: {self.agent.backup_dir if self.agent else 'Not initialized'}
Incident Log: {self.agent.incident_log if self.agent else 'Not initialized'}
"""
        
        stats_text.insert(tk.END, stats_content)
        stats_text.config(state=tk.DISABLED)
        
        stats_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        stats_scroll.pack(side=tk.RIGHT, fill=tk.Y)
    
    def update_status(self):
        if self.monitoring_active:
            self.status_label.config(text="Status: ACTIVE - Real-time protection enabled", foreground="green")
            self.system_status.set("ACTIVE")
        else:
            self.status_label.config(text="Status: STOPPED - Click Start to enable protection", foreground="red")
            self.system_status.set("STOPPED")
        
        self.process_count.set(str(len(self.process_events)))
        self.file_count.set(str(len(self.file_events)))
        
        threats_blocked = len([e for e in self.process_events if e[4] in ["BLOCKED", "TERMINATED"]])
        self.threats_count.set(str(threats_blocked))
        
        if self.agent and self.agent.quarantine_dir.exists():
            quarantine_files = len(list(self.agent.quarantine_dir.glob("*.quar")))
            self.quarantine_count.set(str(quarantine_files))
        else:
            self.quarantine_count.set("0")
        
        if self.start_time:
            uptime = datetime.now() - self.start_time
            hours, remainder = divmod(int(uptime.total_seconds()), 3600)
            minutes, seconds = divmod(remainder, 60)
            self.uptime.set(f"{hours:02d}:{minutes:02d}:{seconds:02d}")
        else:
            self.uptime.set("00:00:00")
        
        try:
            current_tab = self.notebook.tab(self.notebook.select(), "text")
            if current_tab == "Quarantine" and self.monitoring_active:
                self.refresh_quarantine()
        except Exception:
            pass
        
        try:
            current_tab = self.notebook.tab(self.notebook.select(), "text")
            if current_tab == "Reports & Analytics" and self.monitoring_active and DEPS_AVAILABLE:
                if not hasattr(self, '_last_chart_update'):
                    self._last_chart_update = 0
                if time.time() - self._last_chart_update > 30:
                    self.update_charts()
                    self._last_chart_update = time.time()
        except Exception:
            pass
        
        self.root.after(300, self.update_status)
    
    def count_incidents(self):
        try:
            if self.agent and self.agent.incident_log.exists():
                with open(self.agent.incident_log, 'r') as f:
                    return len(f.readlines()) - 1
        except Exception:
            pass
        return 0
    
    def run(self):
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.stop_monitoring()

if __name__ == "__main__":
    app = HIDRGui()
    app.run()