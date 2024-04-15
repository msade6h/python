import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import socket
from scapy.all import *

def convert_url_to_ip(entry_url, entry_ip):
    try:
        url = entry_url.get()
        ip_address = socket.gethostbyname(url)
        entry_ip.delete(0, tk.END)
        entry_ip.insert(0, ip_address)
    except socket.error:
        messagebox.showerror("Error", "Unable to resolve URL to IP.")

def syn_scan(target_ip, port_range, output_text, progress_bar):
    try:
        output_text.delete('1.0', tk.END)
        open_ports = []

        start_port, end_port = map(int, port_range.split('-'))
        if start_port < 1 or end_port > 65535:
            raise ValueError("Port number out of range (1-65535)")

        total_ports = end_port - start_port + 1
        progress_step = 100 / total_ports

        for port in range(start_port, end_port + 1):
            packet = IP(dst=target_ip) / TCP(dport=port, flags='S')
            response = sr1(packet, timeout=1, verbose=0)

            if response is not None and response.haslayer(TCP) and response[TCP].flags == 18:
                open_ports.append(port)

            progress_bar["value"] += progress_step
            progress_bar.update()


        osversion = ""
        packet = IP(dst=target_ip) / TCP(dport=80, flags='S')
        response = sr1(packet, timeout=1, verbose=0)

        if response is not None and response.haslayer(TCP):
            if response[TCP].flags == 18:
                osversion = "Linux"
            elif response[TCP].flags == 20:
                osversion = "Windows"
            elif response[TCP].flags == 24:
                osversion = "OpenBSD"
        else:
            osversion = "Unknown OS"


        return open_ports, osversion

    except ValueError as e:
        messagebox.showerror("Error", str(e))
        return [], ""

def save_scan_results_to_file(filename, target_ip, open_ports, osversion, scan_output):
    with open(filename, 'w') as file:
        file.write(f"Scan results for {target_ip}:\n")
        file.write(f"Open ports: {', '.join(map(str, open_ports))}\n")
        file.write(f"OS version: {osversion}\n\n")
        file.write("Detailed Scan Output:\n")
        file.write(scan_output)

def execute_scan():
    ip_address = entry_ip.get()
    port_range = entry_ports.get()

    progress_bar = ttk.Progressbar(window, orient=tk.HORIZONTAL, length=200, mode='determinate')
    progress_bar.grid(row=4, column=0, columnspan=3, padx=10, pady=5)

    output_text.config(state=tk.NORMAL)
    output_text.delete('1.0', tk.END)
    output_text.insert(tk.END, f"Scanning {ip_address}...\n")
    output_text.config(state=tk.DISABLED)

    window.update() 

    open_ports, osversion = syn_scan(ip_address, port_range, output_text, progress_bar)

    output_text.config(state=tk.NORMAL)
    output_text.delete('1.0', tk.END)
    output_text.insert(tk.END, f"Scan results for {ip_address}:\n")
    output_text.insert(tk.END, f"Open ports: {', '.join(map(str, open_ports))}\n")
    output_text.insert(tk.END, f"OS version: {osversion}\n")
    output_text.config(state=tk.DISABLED)

    progress_bar.destroy()

    if messagebox.askyesno("Save Results", "Do you want to save the scan results?"):
        filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if filename:
            scan_output = output_text.get("1.0", tk.END)  # Get all text from the output_text widget
            save_scan_results_to_file(filename, ip_address, open_ports, osversion, scan_output)
            messagebox.showinfo("Save Successful", f"Scan results saved to {filename}")

window = tk.Tk()
window.title("Network Scanner")

style = ttk.Style()
style.theme_use('alt')
window.configure(bg=style.lookup('TFrame', 'background'))

label_url = tk.Label(window, text="Enter URL:", bg=style.lookup('TLabel', 'background'), fg=style.lookup('TLabel', 'foreground'))
entry_url = tk.Entry(window, width=30)
button_convert_url = tk.Button(window, text="Convert URL to IP", command=lambda: convert_url_to_ip(entry_url, entry_ip), bg='#4CAF50', fg='white')

label_ip = tk.Label(window, text="Target IP:", bg=style.lookup('TLabel', 'background'), fg=style.lookup('TLabel', 'foreground'))
entry_ip = tk.Entry(window, width=30)

label_ports = tk.Label(window, text="Port Range (e.g., 1-100):", bg=style.lookup('TLabel', 'background'), fg=style.lookup('TLabel', 'foreground'))
entry_ports = tk.Entry(window, width=30)

button_execute = tk.Button(window, text="Execute Scan", command=execute_scan, bg='#007BFF', fg='white')

output_text = tk.Text(window, height=15, width=60, wrap=tk.WORD, bg=style.lookup('TText', 'background'), fg=style.lookup('TText', 'foreground'))
output_text.config(state=tk.DISABLED)

label_url.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)
entry_url.grid(row=0, column=1, padx=10, pady=5, sticky=tk.W)
button_convert_url.grid(row=0, column=2, padx=10, pady=5)

label_ip.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)
entry_ip.grid(row=1, column=1, padx=10, pady=5, sticky=tk.W)

label_ports.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)
entry_ports.grid(row=2, column=1, padx=10, pady=5, sticky=tk.W)

button_execute.grid(row=3, column=0, columnspan=3, padx=10, pady=10)

output_text.grid(row=5, column=0, columnspan=3, padx=10, pady=5)

window.mainloop()
