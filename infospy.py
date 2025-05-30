import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
import threading, requests, socket, whois, json
import ssl
import os, subprocess

class SplashScreen(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.overrideredirect(True)
        self.geometry("500x300")
        self.configure(bg="black")
        
        # Center the splash screen
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - 500) // 2
        y = (screen_height - 300) // 2
        self.geometry(f"500x300+{x}+{y}")

        try:
            image = Image.open("/mnt/data/logo/infospy_logo.png")
            image = image.resize((200, 200))
            self.logo_img = ImageTk.PhotoImage(image)
            tk.Label(self, image=self.logo_img, bg="black").pack(pady=10)
        except:
            tk.Label(self, text="[Missing Logo]", fg="white", bg="black").pack(pady=10)
        
        tk.Label(self, text="InfoSpy", font=("Courier", 22, "bold"), fg="lime", bg="black").pack()
        tk.Label(self, text="Info Grabber Toolkit", font=("Courier", 12), fg="lime", bg="black").pack()
        self.after(2500, self.destroy)

class InfoSpyApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("InfoSpy - Info Grabber Toolkit")
        self.geometry("1000x700")
        self.configure(bg="black")

        self.api_key = tk.StringVar()
        self.tabs = ttk.Notebook(self)
        self.tabs.pack(expand=True, fill='both')

        self.recon_tab = ttk.Frame(self.tabs)
        self.network_tab = ttk.Frame(self.tabs)
        self.export_tab = ttk.Frame(self.tabs)

        self.tabs.add(self.recon_tab, text="Recon")
        self.tabs.add(self.network_tab, text="Network")
        self.tabs.add(self.export_tab, text="Export")

        self.results = ""

        self.init_recon_tab()
        self.init_network_tab()
        self.init_export_tab()
        self.check_for_updates()
        self.load_last_profile()
        os.makedirs("logs", exist_ok=True)

    def init_recon_tab(self):
        frame = ttk.LabelFrame(self.recon_tab, text="Target Info")
        frame.pack(fill='both', expand=True, padx=10, pady=10)

        # Command preview
        self.command_preview = tk.Text(frame, height=2, bg="black", fg="lime")
        self.command_preview.grid(row=2, column=0, columnspan=6, sticky="we")
        self.command_preview.insert("end", "[Nmap Command Preview]")
        self.command_preview.config(state='disabled')

        tk.Label(frame, text="Target (IP or Domain):").grid(row=0, column=0, sticky='w')
        self.target_entry = tk.Entry(frame, width=40)
        self.target_entry.grid(row=0, column=1, pady=5)

        tk.Label(frame, text="Shodan API Key (optional):").grid(row=1, column=0, sticky='w')
        tk.Entry(frame, textvariable=self.api_key, width=40).grid(row=1, column=1, pady=5)

        # Spinner label
        self.spinner_label = tk.Label(frame, text="", fg="lime", bg="black", font=("Courier", 10))
        self.spinner_label.grid(row=2, column=0, columnspan=2)

        tk.Button(frame, text="Run Recon", command=self.run_recon_thread).grid(row=3, column=1, sticky='e')
        self.recon_output = tk.Text(frame, height=20)
        tk.Button(frame, text="Copy Output", command=lambda: self.clipboard_append(self.recon_output.get("1.0", tk.END))).grid(row=4, column=2, padx=5)
        tk.Button(frame, text="Paste to Output", command=lambda: self.recon_output.insert(tk.END, self.clipboard_get())).grid(row=4, column=3, padx=5)
        self.recon_output.grid(row=4, column=0, columnspan=2, pady=5)

        self.error_log = tk.Text(frame, height=5, fg="red")
        self.error_log.grid(row=5, column=0, columnspan=2, pady=5)

    def run_recon_thread(self):
        self.recon_output.delete("1.0", tk.END)
        self.error_log.delete("1.0", tk.END)
        self.spinner_label.config(text="[Running recon...]")
        self.set_status("Running recon...")
        self.recon_output.insert("end", "[*] Running recon...\n")
        self.recon_output.update()
        threading.Thread(target=self.run_recon, daemon=True).start()

    def run_recon(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Missing Target", "Please enter an IP or domain.")
            return

        result = f"[+] Recon for {target}\n\n"
        try:
            w = whois.whois(target)
            result += f"[WHOIS]\n{json.dumps(w, indent=2, default=str)}\n\n"
        except Exception as e:
            result += f"[WHOIS ERROR] {e}\n\n"

        try:
            geo = requests.get(f"http://ip-api.com/json/{target}").json()
            result += f"[GeoIP]\n{json.dumps(geo, indent=2)}\n\n"
        except:
            result += "[GeoIP ERROR]\n\n"

        try:
            dns = socket.gethostbyname_ex(target)
            result += f"[DNS Records]\n{dns}\n\n"
        except:
            result += "[DNS ERROR]\n\n"

        try:
            headers = requests.get(f"http://{target}", timeout=5).headers
            result += f"[HTTP Headers]\n{json.dumps(dict(headers), indent=2)}\n\n"
        except:
            result += "[HTTP Header Error]\n\n"

        if self.api_key.get():
            try:
                shodan_data = requests.get(f"https://api.shodan.io/shodan/host/{target}?key={self.api_key.get()}").json()
                result += f"[Shodan]\n{json.dumps(shodan_data, indent=2)}\n\n"
            except:
                result += "[Shodan API Error]\n\n"

        self.results = result
        self.recon_output.insert("end", result + "\n[*] Recon complete.\n")
        self.bell()
        try:
            with open("logs/recon_log.txt", "a") as log:
                log.write(result + "\n")
        except Exception as e:
            self.error_log.insert("end", f"[Log Error] {e}\n")
        self.spinner_label.config(text="[Done]")
        self.set_status("Recon complete")
        self.recon_output.update()

    def init_network_tab(self):
        import yaml
        frame = ttk.LabelFrame(self.network_tab, text="Port Scan")
        frame.pack(fill='both', expand=True, padx=10, pady=10)

        tk.Label(frame, text="Target:").grid(row=0, column=0)
        self.port_target = tk.Entry(frame, width=30)
        self.port_target.grid(row=0, column=1)
        self.nmap_mode = tk.StringVar(value="advanced")
        self.profile_selector = ttk.Combobox(frame, values=[], state="readonly")
        self.profile_selector.grid(row=0, column=2)
        self.profile_selector.set("Select Profile")
        self.profile_selector.bind("<<ComboboxSelected>>", self.load_nmap_profile)

        mode_menu = tk.OptionMenu(frame, self.nmap_mode, "basic", "advanced", "stealth", "firewall bypass")
        mode_menu.grid(row=0, column=3)
        tooltip_label = tk.Label(frame, text="", fg="lime", bg="black")
        tooltip_label.grid(row=1, column=0, columnspan=6)

        def update_tooltip(*args):
            # Get current mode and flags
            mode = self.nmap_mode.get()
            flags = os.environ.get("NMAP_FLAGS", "")
            
            # Update flags if a profile is selected
            profile = self.profile_selector.get()
            if profile and profile != "Select Profile":
                flags = self.nmap_profiles.get(profile, flags)
            
            # Define descriptions for each mode
            descriptions = {
                "basic": "Basic version detection scan",
                "advanced": "Aggressive scan with OS detection",
                "stealth": "Stealthy SYN scan",
                "firewall bypass": "Fragmented packets to evade firewalls"
            }
            
            # Create tooltip text with proper formatting
            full_text = descriptions.get(mode, "")
            if flags:
                full_text += f"\nFlags: {flags}"
                
            # Update the tooltip
            tooltip_label.config(text=full_text)

        # Use trace_add for newer Python versions
        self.nmap_mode.trace_add("write", update_tooltip)
        update_tooltip()

        tk.Button(frame, text="Scan Ports", command=self.run_portscan_thread).grid(row=0, column=4)
        tk.Button(frame, text="Nmap Scan", command=self.run_nmap_thread).grid(row=0, column=5)
        tk.Button(frame, text="Open Last XML", command=self.open_last_xml).grid(row=0, column=6)
        tk.Button(frame, text="Dry Run", command=self.run_nmap_preview).grid(row=0, column=7)
        self.port_output = tk.Text(frame, height=25)
        tk.Button(frame, text="Copy Output", command=lambda: self.clipboard_append(self.port_output.get("1.0", tk.END))).grid(row=1, column=7, sticky='ne')
        tk.Button(frame, text="Paste to Output", command=lambda: self.port_output.insert(tk.END, self.clipboard_get())).grid(row=1, column=6, sticky='ne')
        self.port_output.grid(row=1, column=0, columnspan=6)

        # Load profiles from file
        self.nmap_profiles = {}
        if not os.path.exists("nmap_profiles.yaml"):
            default_profiles = {
                "stealth_scan": "-sS -Pn -T3",
                "firewall_evasion": "-f -D RND:10",
                "aggressive": "-A -O -sV"
            }
            with open("nmap_profiles.yaml", "w") as pf:
                yaml.dump(default_profiles, pf)
        with open("nmap_profiles.yaml", "r") as pf:
            self.nmap_profiles = yaml.safe_load(pf) or {}
            self.profile_selector["values"] = list(self.nmap_profiles.keys())

    def run_portscan_thread(self):
        self.port_output.delete("1.0", tk.END)
        self.set_status("Running port scan...")
        threading.Thread(target=self.run_portscan).start()

    def run_portscan(self):
        self.set_status("Scanning ports...")
        self.set_status("Scanning ports...")
        target = self.port_target.get()
        open_ports = []
        result = f"[+] Port Scan for {target}\n"
        for port in [21, 22, 23, 53, 80, 110, 143, 443, 3306, 8080]:
            try:
                sock = socket.socket()
                sock.settimeout(1)
                sock.connect((target, port))
                open_ports.append(port)
                sock.close()
            except:
                continue
        result += f"[+] Open Ports: {open_ports}\n"
        self.results += result
        self.port_output.insert("end", result + "\n")
        try:
            with open("logs/portscan_log.txt", "a") as log:
                log.write(result + "\n")
        except Exception as e:
            if "No such file or directory" in str(e):
                messagebox.showerror("Nmap Not Found", "Nmap is not installed or not in PATH. " +
                                 "Please install it using: brew install nmap")
            else:
                messagebox.showerror("Nmap Error", str(e))
        self.set_status("Port scan complete")

    def open_profile_editor(self):
        from tkinter import simpledialog
        editor = tk.Toplevel(self)
        editor.title("Edit Nmap Profiles")
        editor.geometry("400x300")
        editor.configure(bg="black")

        profile_list = tk.Listbox(editor)
        profile_list.pack(fill="both", expand=True)
        for name in self.nmap_profiles:
            profile_list.insert("end", name)

        command_entry = tk.Entry(editor)
        command_entry.pack(fill="x")

        def load_selected():
            selection = profile_list.curselection()
            if selection:
                name = profile_list.get(selection[0])
                command_entry.delete(0, tk.END)
                command_entry.insert(0, self.nmap_profiles[name])

        def save_selected():
            selection = profile_list.curselection()
            if selection:
                name = profile_list.get(selection[0])
                self.nmap_profiles[name] = command_entry.get()
                self.save_profiles()
                self.set_status(f"Updated profile: {name}")

        def add_profile():
            name = simpledialog.askstring("New Profile", "Enter profile name:")
            if name:
                self.nmap_profiles[name] = "-sV"
                profile_list.insert("end", name)
                self.save_profiles()

        def delete_profile():
            selection = profile_list.curselection()
            if selection:
                name = profile_list.get(selection[0])
                if messagebox.askyesno("Delete", f"Delete profile '{name}'?"):
                    del self.nmap_profiles[name]
                    profile_list.delete(selection[0])
                    self.save_profiles()

        tk.Button(editor, text="Load", command=load_selected).pack()
        tk.Button(editor, text="Save", command=save_selected).pack()
        tk.Button(editor, text="Add", command=add_profile).pack()
        tk.Button(editor, text="Delete", command=delete_profile).pack()

    def save_profiles(self):
        import yaml
        with open("nmap_profiles.yaml", "w") as pf:
            yaml.dump(self.nmap_profiles, pf)
        self.profile_selector["values"] = list(self.nmap_profiles.keys())

    def export_profiles_zip(self):
        from zipfile import ZipFile
        path = filedialog.asksaveasfilename(defaultextension=".zip", filetypes=[("ZIP files", "*.zip")])
        if path:
            with ZipFile(path, 'w') as zipf:
                zipf.write("nmap_profiles.yaml")
            messagebox.showinfo("Exported", f"Profiles exported to {path}")

    def import_profiles_file(self):
        import yaml
        path = filedialog.askopenfilename(filetypes=[("YAML files", "*.yaml"), ("All files", "*")])
        if path:
            try:
                with open(path, 'r') as f:
                    imported = yaml.safe_load(f)
                if not isinstance(imported, dict):
                    raise ValueError("Imported profile file is not a dictionary.")
                for k, v in imported.items():
                    if not isinstance(k, str) or not isinstance(v, str):
                        raise ValueError(f"Invalid profile format: {k}: {v}")
                self.nmap_profiles.update(imported)
                self.save_profiles()
                messagebox.showinfo("Imported", "Profiles imported successfully.")
            except Exception as e:
                messagebox.showerror("Import Error", f"Failed to import profiles: {e}")
        path = filedialog.askopenfilename(filetypes=[("YAML files", "*.yaml"), ("All files", "*")])
        if path:
            import yaml
            with open(path, 'r') as f:
                imported = yaml.safe_load(f)
                self.nmap_profiles.update(imported)
                self.save_profiles()
                messagebox.showinfo("Imported", "Profiles imported successfully.")

    def init_export_tab(self):
        frame = ttk.LabelFrame(self.export_tab, text="Save Results")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        tk.Button(frame, text="Export to TXT", command=self.export_txt).pack(pady=10)

    def export_txt(self):
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w") as f:
                f.write(self.results)
            messagebox.showinfo("Saved", f"Results saved to {path}")

    def init_menu(self):
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Export Results", command=self.export_txt)
        file_menu.add_command(label="Edit Scan Profiles", command=self.open_profile_editor)
        file_menu.add_command(label="Import Profiles", command=self.import_profiles_file)
        file_menu.add_command(label="Export Profiles ZIP", command=self.export_profiles_zip)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        tools_menu = tk.Menu(menubar, tearoff=0)
        tools_menu.add_command(label="Run Recon", command=self.run_recon_thread)
        tools_menu.add_command(label="Port Scan", command=self.run_portscan_thread)
        menubar.add_cascade(label="Tools", menu=tools_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="Check for Updates", command=self.check_for_updates)
        help_menu.add_command(label="About", command=lambda: messagebox.showinfo("About InfoSpy", """InfoSpy v1.0
macOS Info Grabber Toolkit"""))
        menubar.add_cascade(label="Help", menu=help_menu)

        self.config(menu=menubar)

    def init_status_bar(self):
        self.status = tk.StringVar()
        self.status.set("Ready")
        status_bar = tk.Label(self, textvariable=self.status, bd=1, relief=tk.SUNKEN, anchor=tk.W, bg="black", fg="lime")
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def run_nmap_preview(self):
        target = self.port_target.get().strip()
        if not target:
            messagebox.showwarning("Missing Target", "Please enter a target IP or domain.")
            return
        flags = os.environ.get("NMAP_FLAGS", "")
        cmd = f"nmap {flags} -oX logs/nmap_{target.replace('.', '_')}.xml {target}"
        messagebox.showinfo("Command Preview", cmd)

    def run_nmap_thread(self):
        threading.Thread(target=self.run_nmap).start()

    def run_nmap(self):
        import webbrowser
        target = self.port_target.get().strip()
        if not target:
            messagebox.showwarning("Missing Target", "Please enter a target IP or domain.")
            return

        self.set_status("Running Nmap scan...")
        self.port_output.insert("end", f"[*] Running Nmap scan on {target}...")
        self.port_output.update()

        try:
            mode = self.nmap_mode.get()
            if mode == "basic":
                cmd = ["nmap", "-sV", target]
            elif mode == "stealth":
                cmd = ["nmap", "-sS", "-Pn", target]
            elif mode == "firewall bypass":
                cmd = ["nmap", "-f", "-Pn", target]
            else:  # advanced
                cmd = ["nmap", "-A", "-O", "-sV", "-Pn"]

            custom_flags = os.environ.get("NMAP_FLAGS", "")
            if custom_flags:
                cmd = ["nmap"] + custom_flags.split()

            cmd += ["-oX", f"logs/nmap_{target.replace('.', '_')}.xml", target]
            result = subprocess.check_output(cmd, stderr=subprocess.STDOUT).decode()
            self.results += f"[Nmap Results for {target}]\n{result}\n"
            self.port_output.insert("end", result + "\n")
            with open("logs/nmap_log.txt", "a") as log:
                log.write("[Nmap XML Report Saved] logs/nmap_{}.xml\n".format(target.replace('.', '_')))
                log.write(result + "\n")
        except Exception as e:
            self.port_output.insert("end", f"[Nmap Error] {e}\n")

        self.set_status("Nmap scan complete")

    def open_last_xml(self):
        target = self.port_target.get().strip()
        if not target:
            messagebox.showwarning("Missing Target", "Enter target to find last XML report")
            return
        xml_path = f"logs/nmap_{target.replace('.', '_')}.xml"
        if os.path.exists(xml_path):
            webbrowser.open(f"file://{os.path.abspath(xml_path)}")
        else:
            messagebox.showinfo("Not Found", f"No XML report found for {target}")

    def load_nmap_profile(self, event):
        profile = self.profile_selector.get()
        if profile in self.nmap_profiles:
            os.environ["NMAP_FLAGS"] = self.nmap_profiles[profile]
            self.set_status(f"Loaded profile: {profile}")
            with open(".last_profile", "w") as f:
                f.write(profile)

    def load_last_profile(self):
        if os.path.exists(".last_profile"):
            with open(".last_profile", "r") as f:
                last = f.read().strip()
                if last in self.nmap_profiles:
                    self.profile_selector.set(last)
                    os.environ["NMAP_FLAGS"] = self.nmap_profiles[last]
                    self.set_status(f"Loaded last profile: {last}")

    def set_status(self, text):
        self.status.set(text)

    def check_for_updates(self):
        try:
            remote = requests.get("https://raw.githubusercontent.com/youruser/infospy/main/version.txt").text.strip()
            local = "1.0.0"
            if remote != local:
                messagebox.showinfo("Update Available", f"A new version ({remote}) is available.")
        except:
            print("[!] Update check failed")

def check_ssl_backend():
    version = ssl.OPENSSL_VERSION
    if "LibreSSL" in version:
        messagebox.showwarning(
            "Incompatible SSL Backend",
            f"""Your Python is using LibreSSL, which may cause issues.
Detected: {version}

For best performance, install Python via Homebrew:

brew install python
/opt/homebrew/bin/python3 infospy.py"""
        )

if __name__ == '__main__':
    check_ssl_backend()
    root = InfoSpyApp()
    splash = SplashScreen(root)
    root.withdraw()
    splash.wait_window()
    root.deiconify()
    root.mainloop()
