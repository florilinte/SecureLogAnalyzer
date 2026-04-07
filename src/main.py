import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import time
import csv
import json
import re
import os

class SecureLogAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SecureLogAnalyzer")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)

        # Variables
        self.selected_file = tk.StringVar()
        self.detect_brute_force = tk.BooleanVar(value=True)
        self.detect_privilege = tk.BooleanVar(value=True)
        self.anonymize_data = tk.BooleanVar(value=False)
        self.brute_force_threshold = tk.IntVar(value=5)
        self.analysis_results = [] # Stores dicts of detected events

        self._build_ui()

    def _build_ui(self):
        # --- Top Frame: File Selection (FR-02) ---
        file_frame = tk.LabelFrame(self.root, text="1. Select Log File", padx=10, pady=10)
        file_frame.pack(fill="x", padx=10, pady=5)

        tk.Button(file_frame, text="Browse...", command=self.browse_file, width=15).pack(side="left", padx=5)
        tk.Entry(file_frame, textvariable=self.selected_file, state="readonly", width=80).pack(side="left", fill="x", expand=True, padx=5)

        # --- Middle Frame: Configuration (FR-03, FR-04, FR-15, FR-18) ---
        config_frame = tk.LabelFrame(self.root, text="2. Configure Detection Rules", padx=10, pady=10)
        config_frame.pack(fill="x", padx=10, pady=5)

        # Rule 1: Brute Force
        rule1_frame = tk.Frame(config_frame)
        rule1_frame.pack(fill="x", pady=2)
        tk.Checkbutton(rule1_frame, text="Detect Repeated Failed Logins (Brute Force)", variable=self.detect_brute_force).pack(side="left")
        tk.Label(rule1_frame, text="Threshold:").pack(side="left", padx=(20, 5))
        tk.Spinbox(rule1_frame, from_=1, to=100, textvariable=self.brute_force_threshold, width=5).pack(side="left")

        # Rule 2: Privilege Escalation
        tk.Checkbutton(config_frame, text="Detect Privileged Events (sudo/root usage)", variable=self.detect_privilege).pack(anchor="w", pady=2)
        
        # Privacy
        tk.Checkbutton(config_frame, text="Anonymize IP Addresses & Usernames", variable=self.anonymize_data, fg="blue").pack(anchor="w", pady=2)

        # Analyze Button
        self.btn_analyze = tk.Button(config_frame, text="Run Analysis", command=self.start_analysis, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        self.btn_analyze.pack(pady=10)

        # --- Bottom Frame: Results & Progress (FR-05, FR-07, FR-08) ---
        results_frame = tk.LabelFrame(self.root, text="3. Analysis Results", padx=10, pady=10)
        results_frame.pack(fill="both", expand=True, padx=10, pady=5)

        # Treeview (Table)
        columns = ("Timestamp", "Severity", "Event Type", "Details")
        self.tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side="top", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Progress Bar
        self.progress = ttk.Progressbar(results_frame, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", pady=10)

        # Export Buttons
        export_frame = tk.Frame(results_frame)
        export_frame.pack(fill="x")
        tk.Button(export_frame, text="Export CSV", command=self.export_csv).pack(side="right", padx=5)
        tk.Button(export_frame, text="Export JSON", command=self.export_json).pack(side="right", padx=5)

    def browse_file(self):
        """Opens OS dialog to select a log file (FR-02)"""
        filepath = filedialog.askopenfilename(title="Select Log File", filetypes=(("Log Files", "*.log"), ("Text Files", "*.txt"), ("All Files", "*.*")))
        if filepath:
            self.selected_file.set(filepath)

    def start_analysis(self):
        """Validates input and starts background thread to keep UI responsive (FR-06, PR-06)"""
        filepath = self.selected_file.get()
        if not filepath or not os.path.exists(filepath):
            messagebox.showerror("Error", "Please select a valid log file before running the analysis.")
            return

        # Clear previous results
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.analysis_results.clear()
        
        # Disable button to prevent multiple clicks
        self.btn_analyze.config(state="disabled")
        self.progress["value"] = 0

        # Run analysis in a separate thread
        threading.Thread(target=self._analyze_log_file, args=(filepath,), daemon=True).start()

    def _analyze_log_file(self, filepath):
        """Core parsing and detection engine (FR-10, FR-12, FR-14)"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as file:
                lines = file.readlines()
                total_lines = len(lines)
                
                failed_logins = {}

                for i, line in enumerate(lines):
                    # Basic parsing (Simulating PR-10)
                    timestamp = line[:15] if len(line) > 15 else "Unknown"
                    anonymize = self.anonymize_data.get()

                    # Detection: Privilege Escalation (FR-14)
                    if self.detect_privilege.get() and ("sudo" in line.lower() or "root" in line.lower()):
                        detail = "Privileged command executed" if not anonymize else "Privileged command executed by [REDACTED]"
                        self._add_result(timestamp, "HIGH", "Privileged Action", detail)

                    # Detection: Brute Force / Failed Logins (FR-12)
                    if self.detect_brute_force.get() and "failed password" in line.lower():
                        user_match = re.search(r"for (invalid user )?(\w+)", line.lower())
                        user = user_match.group(2) if user_match else "unknown"
                        
                        failed_logins[user] = failed_logins.get(user, 0) + 1
                        
                        if failed_logins[user] == self.brute_force_threshold.get():
                            detail = f"Repeated failed logins: {user}" if not anonymize else "Repeated failed logins: [REDACTED]"
                            self._add_result(timestamp, "CRITICAL", "Brute Force Attempt", detail)

                    # Update progress bar (FR-08)
                    if i % 100 == 0:  # Update UI every 100 lines
                        self.root.after(0, self._update_progress, (i / total_lines) * 100)
                        time.sleep(0.01) # Simulate complex processing time

            self.root.after(0, self._analysis_complete)

        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Analysis Error", str(e)))
            self.root.after(0, lambda: self.btn_analyze.config(state="normal"))

    def _add_result(self, timestamp, severity, event_type, details):
        """Thread-safe way to add data to the Treeview and internal list"""
        event_data = {"timestamp": timestamp, "severity": severity, "type": event_type, "details": details}
        self.analysis_results.append(event_data)
        
        # UI updates must happen on the main thread
        self.root.after(0, lambda: self.tree.insert("", "end", values=(timestamp, severity, event_type, details)))

    def _update_progress(self, value):
        self.progress["value"] = value

    def _analysis_complete(self):
        self.progress["value"] = 100
        self.btn_analyze.config(state="normal")
        messagebox.showinfo("Analysis Complete", f"Finished parsing log file.\nDetected {len(self.analysis_results)} suspicious events.")

    def export_csv(self):
        """Exports data to CSV (FR-07)"""
        if not self.analysis_results:
            messagebox.showwarning("Export Error", "No results to export.")
            return
            
        filepath = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if filepath:
            with open(filepath, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=["timestamp", "severity", "type", "details"])
                writer.writeheader()
                writer.writerows(self.analysis_results)
            messagebox.showinfo("Export Success", "Data exported successfully!")

    def export_json(self):
        """Exports data to JSON (FR-07)"""
        if not self.analysis_results:
            messagebox.showwarning("Export Error", "No results to export.")
            return
            
        filepath = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if filepath:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(self.analysis_results, f, indent=4)
            messagebox.showinfo("Export Success", "Data exported successfully!")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecureLogAnalyzerApp(root)
    root.mainloop()