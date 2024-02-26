import tkinter as tk
from tkinter import ttk, messagebox
import socket
import threading

class PortScannerGUI:
    def __init__(self, master):
        self.master = master
        self.master.title("Port Scanner GUI")

        self.target_label = tk.Label(master, text="Enter IP Address:")
        self.target_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.target_entry = tk.Entry(master)
        self.target_entry.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)

        self.port_label = tk.Label(master, text="Enter Port Numbers (comma-separated):")
        self.port_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

        self.port_entry = tk.Entry(master)
        self.port_entry.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)

        self.scan_button = tk.Button(master, text="Start Scan", command=self.start_scan)
        self.scan_button.grid(row=2, column=0, columnspan=2, pady=10)

        self.result_text = tk.Text(master, wrap=tk.WORD, width=40, height=15)
        self.result_text.grid(row=3, column=0, columnspan=2, padx=10, pady=5)

    def start_scan(self):
        self.result_text.delete(1.0, tk.END)  # Clear previous results
        target = self.target_entry.get()
        port_str = self.port_entry.get()

        if not target or not port_str:
            messagebox.showerror("Error", "Please enter both IP Address and Port Numbers.")
            return

        try:
            ports = [int(port) for port in port_str.split(",")]
        except ValueError:
            messagebox.showerror("Error", "Invalid port number(s). Please enter valid port numbers.")
            return

        self.result_text.insert(tk.END, f"Scanning {target}...\n")

        # Run the port scan in a separate thread to avoid freezing the GUI
        scan_thread = threading.Thread(target=self.perform_scan, args=(target, ports))
        scan_thread.start()

    def perform_scan(self, target, ports):
        for port in ports:
            result = self.scan_port(target, port)
            self.result_text.insert(tk.END, result + "\n")
            self.result_text.yview(tk.END)  # Auto-scroll to the bottom

    def scan_port(self, ip_address, port):
        try:
            sock = socket.socket()
            sock.settimeout(1)  # Timeout for socket connection
            sock.connect((ip_address, port))
            sock.close()
            return f"[+] Port {port} Open"
        except (socket.timeout, socket.error):
            return f"[-] Port {port} Closed"

if __name__ == "__main__":
    root = tk.Tk()
    app = PortScannerGUI(root)
    root.mainloop()