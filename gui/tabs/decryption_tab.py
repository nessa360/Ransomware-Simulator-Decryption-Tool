import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
from core.simulator import RansomwareSimulator

class DecryptionTab(ttk.Frame):
    def __init__(self, parent, simulator: RansomwareSimulator):
        super().__init__(parent)
        self.simulator = simulator
        self.setup_ui()
        
    def setup_ui(self):
        frame = ttk.LabelFrame(self, text="Decrypt Files")
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Encrypted directory
        ttk.Label(frame, text="Encrypted Directory:").grid(row=0, column=0, padx=5, pady=5, sticky='w')
        self.encrypted_dir_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.encrypted_dir_var).grid(row=0, column=1, padx=5, pady=5, sticky='we')
        ttk.Button(frame, text="Browse", command=self.browse_encrypted_dir).grid(row=0, column=2, padx=5, pady=5)
        
        # Key file
        ttk.Label(frame, text="Key File:").grid(row=1, column=0, padx=5, pady=5, sticky='w')
        self.decrypt_key_file_var = tk.StringVar()
        ttk.Entry(frame, textvariable=self.decrypt_key_file_var).grid(row=1, column=1, padx=5, pady=5, sticky='we')
        ttk.Button(frame, text="Browse", command=self.browse_decrypt_key_file).grid(row=1, column=2, padx=5, pady=5)
        
        # Decrypt button
        ttk.Button(frame, text="Decrypt Files", command=self.decrypt_files).grid(row=2, column=0, columnspan=3, padx=5, pady=20)
        
        # Status
        self.decrypt_status_var = tk.StringVar(value="Ready")
        ttk.Label(frame, textvariable=self.decrypt_status_var).grid(row=3, column=0, columnspan=3, padx=5, pady=5)
        
        # Progress bar
        self.decrypt_progress = ttk.Progressbar(frame, orient=tk.HORIZONTAL, length=200, mode='indeterminate')
        self.decrypt_progress.grid(row=4, column=0, columnspan=3, padx=5, pady=5, sticky='we')
        
        frame.columnconfigure(1, weight=1)
        
    def browse_encrypted_dir(self):
        directory = filedialog.askdirectory(title="Select Encrypted Directory")
        if directory:
            self.encrypted_dir_var.set(directory)
            
    def browse_decrypt_key_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Key File",
            defaultextension=".key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if file_path:
            self.decrypt_key_file_var.set(file_path)
            
    def decrypt_files(self):
        encrypted_dir = self.encrypted_dir_var.get()
        key_file = self.decrypt_key_file_var.get()
        
        if not encrypted_dir or not key_file:
            messagebox.showerror("Error", "Please fill in all required fields")
            return
            
        self.decrypt_progress.start()
        self.decrypt_status_var.set("Loading key and decrypting files...")
        
        def decrypt_thread():
            try:
                if not self.simulator.load_key_from_file(key_file):
                    raise Exception("Invalid key file")
                    
                count = self.simulator.decrypt_directory(encrypted_dir)
                
                self.after(0, lambda: self.decrypt_progress.stop())
                self.after(0, lambda: self.decrypt_status_var.set(f"Decryption complete. {count} files restored."))
                self.after(0, lambda: messagebox.showinfo("Decryption Complete", 
                    f"Successfully decrypted {count} files in {encrypted_dir}."))
            except Exception as e:
                self.after(0, lambda: self.decrypt_progress.stop())
                self.after(0, lambda: self.decrypt_status_var.set(f"Error: {str(e)}"))
                self.after(0, lambda: messagebox.showerror("Error", str(e)))
                
        thread = threading.Thread(target=decrypt_thread)
        thread.daemon = True
        thread.start()
