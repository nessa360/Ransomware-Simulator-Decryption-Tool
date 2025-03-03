import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from core.simulator import RansomwareSimulator

class RecoveryTab(ttk.Frame):
    def __init__(self, parent, simulator: RansomwareSimulator):
        super().__init__(parent)
        self.simulator = simulator
        self.setup_ui()
        
    def setup_ui(self):
        frame = ttk.LabelFrame(self, text="Key Recovery Tool")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Sample encrypted file
        ttk.Label(frame, text="Sample Encrypted File:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.sample_file_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.sample_file_var).grid(row=0, column=1, padx=5, pady=5, sticky='we')
        ttk.Button(frame, text="Browse", command=self.browse_sample_file).grid(row=0, column=2, padx=5, pady=5)
        
        # Password used
        ttk.Label(frame, text="Original Password (if known):").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.recovery_password_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.recovery_password_var).grid(row=1, column=1, padx=5, pady=5, sticky='we')
        
        # Salt value (if known)
        ttk.Label(frame, text="Salt Value (if known, hex):").grid(row=2, column=0, padx=5, pady=5, sticky='w')
        self.salt_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.salt_var).grid(row=2, column=1, padx=5, pady=5, sticky='we')
        
        # Save recovered key
        ttk.Label(frame, text="Save Recovered Key To:").grid(row=3, column=0, padx=5, pady=5, sticky='w')
        self.recovered_key_file_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.recovered_key_file_var).grid(row=3, column=1, padx=5, pady=5, sticky='we')
        ttk.Button(frame, text="Browse", command=self.browse_recovered_key_file).grid(row=3, column=2, padx=5, pady=5)
        
        # Recovery button
        ttk.Button(frame, text="Attempt Key Recovery", command=self.recover_key).grid(row=4, column=0, columnspan=3, padx=5, pady=20)
        
        # Status
        self.recovery_status_var = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.recovery_status_var).grid(row=5, column=0, columnspan=3, padx=5, pady=5)
        
        # Progress bar
        self.recovery_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.recovery_progress.grid(row=6, column=0, columnspan=3, padx=5, pady=5, sticky='we')
        
        frame.columnconfigure(1, weight=1)
        
    def browse_sample_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Sample Encrypted File",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )
        if file_path:
            self.sample_file_var.set(file_path)
            
    def browse_recovered_key_file(self):
        file_path = filedialog.asksaveasfilename(
            title="Save Recovered Key File",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if file_path:
            self.recovered_key_file_var.set(file_path)
            
    def recover_key(self):
        sample_file = self.sample_file_var.get()
        password = self.recovery_password_var.get()
        salt_hex = self.salt_var.get()
        recovery_file = self.recovered_key_file_var.get()
        
        if not sample_file or not recovery_file:
            messagebox.showerror("Error", "Please provide a sample encrypted file and recovery key path")
            return
            
        if not password and not salt_hex:
            messagebox.showerror("Error", "Please provide either a password or salt value")
            return
            
        self.recovery_progress.start()
        self.recovery_status_var.set("Attempting key recovery...")
        
        def recovery_thread():
            try:
                if salt_hex:
                    try:
                        self.simulator.salt = bytes.fromhex(salt_hex)
                    except:
                        raise Exception("Invalid salt hex value")
                
                key = self.simulator.generate_recovery_key(sample_file, password)
                
                if key:
                    self.simulator.save_key_to_file(recovery_file)
                    self.after(0, lambda: self.recovery_progress.stop())
                    self.after(0, lambda: self.recovery_status_var.set("Key recovered successfully!"))
                    self.after(0, lambda: messagebox.showinfo("Recovery Complete", 
                        f"Successfully recovered decryption key.\nSaved to {recovery_file}"))
                else:
                    self.after(0, lambda: self.recovery_progress.stop())
                    self.after(0, lambda: self.recovery_status_var.set("Failed to recover key"))
                    self.after(0, lambda: messagebox.showerror("Recovery Failed", 
                        "Could not recover the decryption key with the provided information."))
            except Exception as e:
                self.after(0, lambda: self.recovery_progress.stop())
                self.after(0, lambda: self.recovery_status_var.set(f"Error: {str(e)}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                
        thread = threading.Thread(target=recovery_thread)
        thread.daemon = True
        thread.start()
