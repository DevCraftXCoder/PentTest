import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, filedialog
import socket
import threading
import queue
import paramiko
import requests
import time
import ssl
import json
from datetime import datetime
import random
from concurrent.futures import ThreadPoolExecutor
import multiprocessing
import os

# GUI Style Constants
BACKGROUND_COLOR = "#2b2b2b"
FOREGROUND_COLOR = "#ffffff"
ACCENT_COLOR = "#007acc"
BUTTON_BG = "#3c3c3c"
BUTTON_FG = "#ffffff"
ENTRY_BG = "#3c3c3c"
ENTRY_FG = "#ffffff"
TEXT_BG = "#1e1e1e"
TEXT_FG = "#ffffff"
FONT = ("Segoe UI", 10)
HEADER_FONT = ("Segoe UI", 12, "bold")

# Constants
MAX_THREADS = multiprocessing.cpu_count() * 2  # Optimal thread count
CHUNK_SIZE = 100  # Number of ports per chunk for scanning
TIMEOUT = 1.0  # Socket timeout in seconds

# User-Agent rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
]

class PortScanner:
    def __init__(self, target, result_queue, timeout=TIMEOUT):
        self.target = target
        self.result_queue = result_queue
        self.timeout = timeout
        self.executor = ThreadPoolExecutor(max_workers=MAX_THREADS)

    def scan_port(self, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                result = s.connect_ex((self.target, port))
                if result == 0:
                    service = "unknown"
                    try:
                        service = socket.getservbyport(port)
                    except:
                        pass
                    return port, service
        except:
            pass
        return None

    def scan_ports(self, start_port, end_port, progress_callback=None):
        ports = range(start_port, end_port + 1)
        total_ports = len(ports)
        completed = 0

        # Split ports into chunks for batch processing
        port_chunks = [ports[i:i + CHUNK_SIZE] for i in range(0, len(ports), CHUNK_SIZE)]
        
        for chunk in port_chunks:
            futures = [self.executor.submit(self.scan_port, port) for port in chunk]
            for future in futures:
                result = future.result()
                if result:
                    self.result_queue.put(result)
                completed += 1
                if progress_callback:
                    progress_callback(completed / total_ports * 100)

    def cleanup(self):
        self.executor.shutdown(wait=False)

class RateLimit:
    def __init__(self, calls_per_second=1):
        self.delay = 1.0 / float(calls_per_second)
        self.last_call = 0
        self._lock = threading.Lock()

    def wait(self):
        with self._lock:
            now = time.time()
            if self.last_call + self.delay > now:
                time.sleep(self.last_call + self.delay - now)
            self.last_call = time.time()

rate_limiter = RateLimit(calls_per_second=2)

def validate_target(target):
    try:
        # Check if IP
        socket.inet_aton(target)
        return True
    except socket.error:
        # Check if hostname
        try:
            socket.gethostbyname(target)
            return True
        except socket.gaierror:
            return False

def save_results():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_filename = f"pentest_results_{timestamp}.txt"
    file_path = filedialog.asksaveasfilename(
        defaultextension=".txt",
        initialfile=default_filename,
        filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
    )
    if file_path:
        with open(file_path, 'w') as f:
            f.write(result_text.get(1.0, tk.END))
        messagebox.showinfo("Success", "Results saved successfully!")

def load_wordlist():
    file_path = filedialog.askopenfilename(
        title="Select Password List",
        filetypes=(("Text files", "*.txt"), ("All files", "*.*"))
    )
    if file_path:
        try:
            with open(file_path, 'r') as f:
                passwords = f.read().splitlines()
                return passwords
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load wordlist: {str(e)}")
            return ["123456", "password", "admin", "root"]
    return ["123456", "password", "admin", "root"]

def check_ssl_security():
    url = entry_target_web.get()
    if not url.startswith(('http://', 'https://')):
        messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
        return
    
    try:
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, f"Checking SSL security for {url}...\n")
        response = requests.get(url, verify=True)
        hostname = url.split('://')[1].split('/')[0]
        cert = ssl.get_server_certificate((hostname, 443))
        result_text.insert(tk.END, "✓ SSL certificate is valid\n")
    except requests.exceptions.SSLError:
        result_text.insert(tk.END, "✗ Invalid SSL certificate\n")
    except Exception as e:
        result_text.insert(tk.END, f"✗ SSL check failed: {str(e)}\n")

def generate_report():
    report = {
        "timestamp": datetime.now().isoformat(),
        "target": entry_target.get(),
        "scan_results": result_text.get(1.0, tk.END),
    }
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_path = filedialog.asksaveasfilename(
        defaultextension=".json",
        initialfile=f"pentest_report_{timestamp}.json",
        filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
    )
    
    if file_path:
        with open(file_path, 'w') as f:
            json.dump(report, f, indent=4)
        messagebox.showinfo("Success", "Report generated successfully!")

def scan_network():
    target = entry_target.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target IP/URL")
        return
        
    if not validate_target(target):
        messagebox.showerror("Error", "Invalid target IP/URL")
        return
    
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, f"Quick scanning {target}...\n")
    
    # Create progress bar
    progress = ttk.Progressbar(scanner_tab, mode='determinate')
    progress.pack(pady=5)
    
    def update_progress(value):
        progress['value'] = value
        root.update_idletasks()
    
    def scan_thread():
        try:
            result_queue = queue.Queue()
            scanner = PortScanner(target, result_queue)
            
            # Common ports to scan
            common_ports = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 8080, 8443]
            
            scanner.scan_ports(min(common_ports), max(common_ports), update_progress)
            
            # Process results
            open_ports = []
            while not result_queue.empty():
                port, service = result_queue.get()
                open_ports.append((port, service))
            
            # Sort and display results
            open_ports.sort()
            for port, service in open_ports:
                result_text.insert(tk.END, f"[+] Port {port} ({service}) is open\n")
                
            if not open_ports:
                result_text.insert(tk.END, "No open ports found.\n")
                
            result_text.insert(tk.END, "Quick scan completed.\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error during scan: {str(e)}\n")
        finally:
            progress.destroy()
            scanner.cleanup()
    
    threading.Thread(target=scan_thread, daemon=True).start()

def nmap_scan():
    target = entry_target.get()
    if not target:
        messagebox.showerror("Error", "Please enter a target IP/URL")
        return
        
    if not validate_target(target):
        messagebox.showerror("Error", "Invalid target IP/URL")
        return
    
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, f"Full scanning {target}...\n")
    
    # Create progress bar
    progress = ttk.Progressbar(scanner_tab, mode='determinate')
    progress.pack(pady=5)
    
    def update_progress(value):
        progress['value'] = value
        root.update_idletasks()
    
    def scan_thread():
        try:
            result_queue = queue.Queue()
            scanner = PortScanner(target, result_queue)
            
            # Resolve hostname to IP
            ip = socket.gethostbyname(target)
            result_text.insert(tk.END, f"IP Address: {ip}\n\n")
            
            # Scan all ports from 1 to 1024
            scanner.scan_ports(1, 1024, update_progress)
            
            # Process results
            open_ports = []
            while not result_queue.empty():
                port, service = result_queue.get()
                open_ports.append((port, service))
            
            # Sort and display results
            open_ports.sort()
            for port, service in open_ports:
                result_text.insert(tk.END, f"Port {port} ({service}): open\n")
                
            if not open_ports:
                result_text.insert(tk.END, "No open ports found.\n")
                
            result_text.insert(tk.END, "\nFull scan completed.\n")
        except Exception as e:
            result_text.insert(tk.END, f"Error during scan: {str(e)}\n")
        finally:
            progress.destroy()
            scanner.cleanup()
    
    threading.Thread(target=scan_thread, daemon=True).start()

def ssh_brute_force():
    host = entry_target_ssh.get()
    user = entry_username.get()
    
    if not host or not user:
        messagebox.showerror("Error", "Please enter both target IP and username")
        return
        
    if not validate_target(host):
        messagebox.showerror("Error", "Invalid target IP")
        return
    
    passwords = load_wordlist()
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, f"Starting SSH brute force on {host} for user {user}...\n")
    
    for password in passwords:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(host, username=user, password=password, timeout=3)
            result_text.insert(tk.END, f"[+] Success! Password found: {password}\n")
            client.close()
            return
        except paramiko.AuthenticationException:
            result_text.insert(tk.END, f"[-] Failed: {password}\n")
        except Exception as e:
            result_text.insert(tk.END, f"[!] Error: {str(e)}\n")
            break
    result_text.insert(tk.END, "Brute force attempt completed.\n")

def check_http_vulnerabilities():
    url = entry_target_web.get()
    if not url:
        messagebox.showerror("Error", "Please enter a target URL")
        return
        
    if not url.startswith(('http://', 'https://')):
        messagebox.showerror("Error", "Please enter a valid URL starting with http:// or https://")
        return
        
    test_paths = [
        "/admin", "/phpmyadmin", "/wp-login.php", "/robots.txt",
        "/wp-admin", "/administrator", "/admin.php", "/.env",
        "/backup", "/wp-config.php", "/config.php", "/server-status",
        "/.git/config", "/login", "/cms"
    ]
    
    result_text.delete('1.0', tk.END)
    result_text.insert(tk.END, f"Scanning {url} for vulnerabilities...\n\n")
    
    progress = ttk.Progressbar(web_tab, mode='determinate', maximum=len(test_paths))
    progress.pack(pady=5)
    
    def scan_thread():
        try:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            for i, path in enumerate(test_paths):
                try:
                    full_url = url.rstrip('/') + path
                    response = requests.get(full_url, headers=headers, timeout=5, verify=False)
                    if response.status_code == 200:
                        result_text.insert(tk.END, f"[+] Found: {full_url} (Status: {response.status_code})\n")
                    elif response.status_code == 401 or response.status_code == 403:
                        result_text.insert(tk.END, f"[!] Protected: {full_url} (Status: {response.status_code})\n")
                    progress['value'] = i + 1
                    rate_limiter.wait()
                except requests.exceptions.RequestException as e:
                    result_text.insert(tk.END, f"[-] Error accessing {full_url}: {str(e)}\n")
            result_text.insert(tk.END, "\nVulnerability scan completed.\n")
        finally:
            progress.destroy()
            
    threading.Thread(target=scan_thread, daemon=True).start()

def about():
    messagebox.showinfo("About", "GUI-Based Network Pentesting Suite\nDeveloped in Python using Tkinter, Scapy, and Nmap")

# GUI Setup
root = tk.Tk()
root.title("Network Pentesting Suite")
root.geometry("900x700")
root.configure(bg=BACKGROUND_COLOR)

# Set application icon
try:
    # First attempt: Try to load the icon directly
    root.iconbitmap("NepSmug.ico")
except Exception as e:
    try:
        # Second attempt: Try to use PhotoImage as an alternative
        icon = tk.PhotoImage(file="NepSmug.png")
        root.iconphoto(True, icon)
    except Exception as e2:
        try:
            # Third attempt: Try with absolute path if available
            script_dir = os.path.dirname(os.path.abspath(__file__))
            icon_path = os.path.join(script_dir, "NepSmug.ico")
            root.iconbitmap(icon_path)
        except Exception as e3:
            print(f"Could not load icon: {e3}")
            # Continue without an icon

# Configure styles
style = ttk.Style()
style.theme_use('default')
style.configure('TNotebook', background=BACKGROUND_COLOR)
style.configure('TNotebook.Tab', padding=[10, 5], font=FONT, background=BUTTON_BG, foreground=BUTTON_FG)
style.map('TNotebook.Tab', background=[('selected', ACCENT_COLOR)])
style.configure('TFrame', background=BACKGROUND_COLOR)
style.configure('TButton', 
    padding=[10, 5], 
    font=FONT, 
    background=BUTTON_BG, 
    foreground=BUTTON_FG)
style.configure('TProgressbar', 
    background=ACCENT_COLOR,
    troughcolor=BACKGROUND_COLOR)
style.configure('TLabelframe', 
    background=BACKGROUND_COLOR,
    foreground=FOREGROUND_COLOR)
style.configure('TLabelframe.Label', 
    background=BACKGROUND_COLOR,
    foreground=FOREGROUND_COLOR,
    font=HEADER_FONT)

# Create notebook for tabs
notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both', padx=10, pady=10)

# Port Scanner Tab
scanner_tab = ttk.Frame(notebook)
notebook.add(scanner_tab, text='🔍 Port Scanner')

# Header
header_frame = ttk.Frame(scanner_tab)
header_frame.pack(fill='x', padx=20, pady=10)
header_label = tk.Label(header_frame, 
    text="Network Port Scanner",
    font=HEADER_FONT,
    bg=BACKGROUND_COLOR,
    fg=FOREGROUND_COLOR)
header_label.pack()

# Input frame
input_frame = ttk.Frame(scanner_tab)
input_frame.pack(fill='x', padx=20, pady=10)

label_target = tk.Label(input_frame, 
    text="Target IP/URL:",
    font=FONT,
    bg=BACKGROUND_COLOR,
    fg=FOREGROUND_COLOR)
label_target.pack(pady=5)

entry_target = tk.Entry(input_frame, 
    width=40,
    font=FONT,
    bg=ENTRY_BG,
    fg=ENTRY_FG,
    insertbackground=FOREGROUND_COLOR)
entry_target.pack()

# Button frame
scan_frame = ttk.Frame(scanner_tab)
scan_frame.pack(pady=10)

btn_scan = ttk.Button(scan_frame, 
    text="🚀 Quick Network Scan",
    command=scan_network)
btn_scan.pack(side=tk.LEFT, padx=5)

btn_nmap = ttk.Button(scan_frame, 
    text="🌐 Full Port Scan",
    command=nmap_scan)
btn_nmap.pack(side=tk.LEFT, padx=5)

# SSH Tools Tab
ssh_tab = ttk.Frame(notebook)
notebook.add(ssh_tab, text='🔑 SSH Tools')

# Header
ssh_header = tk.Label(ssh_tab, 
    text="SSH Brute Force Tool",
    font=HEADER_FONT,
    bg=BACKGROUND_COLOR,
    fg=FOREGROUND_COLOR)
ssh_header.pack(pady=10)

ssh_input_frame = ttk.Frame(ssh_tab)
ssh_input_frame.pack(fill='x', padx=20, pady=10)

label_ssh_target = tk.Label(ssh_input_frame, 
    text="Target IP:",
    font=FONT,
    bg=BACKGROUND_COLOR,
    fg=FOREGROUND_COLOR)
label_ssh_target.pack(pady=5)

entry_target_ssh = tk.Entry(ssh_input_frame, 
    width=40,
    font=FONT,
    bg=ENTRY_BG,
    fg=ENTRY_FG,
    insertbackground=FOREGROUND_COLOR)
entry_target_ssh.pack()

label_username = tk.Label(ssh_input_frame, 
    text="SSH Username:",
    font=FONT,
    bg=BACKGROUND_COLOR,
    fg=FOREGROUND_COLOR)
label_username.pack(pady=5)

entry_username = tk.Entry(ssh_input_frame, 
    width=20,
    font=FONT,
    bg=ENTRY_BG,
    fg=ENTRY_FG,
    insertbackground=FOREGROUND_COLOR)
entry_username.pack()

ssh_frame = ttk.Frame(ssh_tab)
ssh_frame.pack(pady=10)

btn_ssh = ttk.Button(ssh_frame, 
    text="🔓 Start SSH Brute Force",
    command=ssh_brute_force)
btn_ssh.pack(pady=5)

btn_wordlist = ttk.Button(ssh_frame, 
    text="📝 Load Custom Wordlist",
    command=load_wordlist)
btn_wordlist.pack(pady=5)

# Web Scanner Tab
web_tab = ttk.Frame(notebook)
notebook.add(web_tab, text='🌐 Web Scanner')

web_header = tk.Label(web_tab, 
    text="Web Vulnerability Scanner",
    font=HEADER_FONT,
    bg=BACKGROUND_COLOR,
    fg=FOREGROUND_COLOR)
web_header.pack(pady=10)

web_input_frame = ttk.Frame(web_tab)
web_input_frame.pack(fill='x', padx=20, pady=10)

label_web_target = tk.Label(web_input_frame, 
    text="Target URL:",
    font=FONT,
    bg=BACKGROUND_COLOR,
    fg=FOREGROUND_COLOR)
label_web_target.pack(pady=5)

entry_target_web = tk.Entry(web_input_frame, 
    width=40,
    font=FONT,
    bg=ENTRY_BG,
    fg=ENTRY_FG,
    insertbackground=FOREGROUND_COLOR)
entry_target_web.pack()

web_frame = ttk.Frame(web_tab)
web_frame.pack(pady=10)

btn_http = ttk.Button(web_frame, 
    text="🔍 Scan Web Vulnerabilities",
    command=check_http_vulnerabilities)
btn_http.pack(side=tk.LEFT, padx=5)

btn_ssl = ttk.Button(web_frame, 
    text="🔒 Check SSL Security",
    command=check_ssl_security)
btn_ssl.pack(side=tk.LEFT, padx=5)

# About Tab
about_tab = ttk.Frame(notebook)
notebook.add(about_tab, text='ℹ️ About')

about_text = tk.Label(about_tab, 
    text="""GUI-Based Network Pentesting Suite
Version 1.0

Features:
🔍 Port Scanning
🔑 SSH Brute Force
🌐 Web Vulnerability Scanning
🔒 SSL Security Checks
📝 Custom Wordlist Support
📊 Report Generation

Created by DevCraftXCoder
Developed in Python using Tkinter
Use responsibly and only on authorized systems.""",
    justify=tk.LEFT,
    pady=20,
    font=FONT,
    bg=BACKGROUND_COLOR,
    fg=FOREGROUND_COLOR)
about_text.pack(expand=True)

# Results area
result_frame = ttk.LabelFrame(root, text="Scan Results")
result_frame.pack(fill='both', expand=True, padx=10, pady=5)

result_text = scrolledtext.ScrolledText(result_frame, 
    width=70,
    height=15,
    font=("Consolas", 10),
    bg=TEXT_BG,
    fg=TEXT_FG,
    insertbackground=FOREGROUND_COLOR)
result_text.pack(fill='both', expand=True, padx=5, pady=5)

# Bottom toolbar
toolbar = ttk.Frame(root)
toolbar.pack(fill='x', padx=10, pady=5)

btn_save = ttk.Button(toolbar, 
    text="💾 Save Results",
    command=save_results)
btn_save.pack(side=tk.LEFT, padx=5)

btn_report = ttk.Button(toolbar, 
    text="📊 Generate Report",
    command=generate_report)
btn_report.pack(side=tk.LEFT, padx=5)

# Add menu bar
menubar = tk.Menu(root)
root.config(menu=menubar)

file_menu = tk.Menu(menubar, tearoff=0, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
menubar.add_cascade(label="File", menu=file_menu)
file_menu.add_command(label="💾 Save Results", command=save_results)
file_menu.add_command(label="📊 Generate Report", command=generate_report)
file_menu.add_separator()
file_menu.add_command(label="❌ Exit", command=root.quit)

tools_menu = tk.Menu(menubar, tearoff=0, bg=BACKGROUND_COLOR, fg=FOREGROUND_COLOR)
menubar.add_cascade(label="Tools", menu=tools_menu)
tools_menu.add_command(label="📝 Load Custom Wordlist", command=load_wordlist)
tools_menu.add_command(label="🔒 Check SSL Security", command=check_ssl_security)

# Center window on screen
window_width = 900
window_height = 700
screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
center_x = int(screen_width/2 - window_width/2)
center_y = int(screen_height/2 - window_height/2)
root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')

root.mainloop()
