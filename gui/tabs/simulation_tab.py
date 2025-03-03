import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from core.simulator import RansomwareSimulator

class SimulationTab(ttk.Frame):
    def __init__(self, parent, simulator: RansomwareSimulator):
        super().__init__(parent)
        self.simulator = simulator
        self.setup_ui()
        
    def setup_ui(self):
        frame = ttk.LabelFrame(self, text="Ransomware Simulation")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Password entry
        ttk.Label(frame, text="Enter encryption password:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(frame, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=0, column=1, padx=5, pady=5, sticky='we')
        
        # Target directory
        ttk.Label(frame, text="Target Directory:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.target_dir_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.target_dir_var).grid(row=1, column=1, padx=5, pady=5, sticky='we')
        ttk.Button(frame, text="Browse", command=self.browse_target_dir).grid(row=1, column=2, padx=5, pady=5)
        
        # Save key file
        ttk.Label(frame, text="Save Key File:").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.key_file_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.key_file_var).grid(row=2, column=1, padx=5, pady=5, sticky='we')
        ttk.Button(frame, text="Browse", command=self.browse_key_file).grid(row=2, column=2, padx=5, pady=5)
        
        # File types to encrypt
        ttk.Label(frame, text="File Extensions:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.extensions_var = tk.StringVar(value=", ".join(self.simulator.target_extensions))
        ttk.Entry(frame, textvariable=self.extensions_var).grid(row=3, column=1, columnspan=2, padx=5, pady=5, sticky='we')
        
        # Execute button
        ttk.Button(frame, text="Start Simulation", command=self.start_simulation).grid(row=4, column=0, columnspan=3, padx=5, pady=20)
        
        # Status
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.status_var).grid(row=5, column=0, columnspan=3, padx=5, pady=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.progress.grid(row=6, column=0, columnspan=3, padx=5, pady=5, sticky='we')
        
        frame.columnconfigure(1, weight=1)
        
    def browse_target_dir(self):
        directory = filedialog.askdirectory(title="Select Target Directory")
        if directory:
            self.target_dir_var.set(directory)
            
    def browse_key_file(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Key File",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if file_path:
            self.key_file_var.set(file_path)
            
    def start_simulation(self):
        password = self.password_var.get()
        target_dir = self.target_dir_var.get()
        key_file = self.key_file_var.get()
        extensions = self.extensions_var.get().split(',')
        
        if not password or not target_dir or not key_file:
            messagebox.showerror("Error", "Please fill in all required fields")
            return
            
        self.simulator.target_extensions = [ext.strip() for ext in extensions]
        self.progress.start()
        self.status_var.set("Encrypting files...")
        
        key, salt = self.simulator.init_encryption(password)
        
        def encrypt_thread():
            try:
                count = self.simulator.encrypt_directory(target_dir)
                self.simulator.save_key_to_file(key_file)
                
                self.after(0, lambda: self.progress.stop())
                self.after(0, lambda: self.status_var.set(f"Encryption complete. {count} files encrypted. Key saved."))
                self.after(0, lambda: messagebox.showinfo("Simulation Complete", 
                    f"Encrypted {count} files in {target_dir}.\nKey saved to {key_file}.\n\nIMPORTANT: Keep this key safe to decrypt your files later!"))
            except Exception as e:
                self.after(0, lambda: self.progress.stop())
                self.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                
        thread = threading.Thread(target=encrypt_thread)
        thread.daemon = True
        thread.start()
