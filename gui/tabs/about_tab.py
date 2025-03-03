import tkinter as tk
from tkinter import ttk

class AboutTab(ttk.Frame):
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        frame = ttk.Frame(self)
        frame.pack(fill='both', expand=True, padx=10, pady=10)
        
        about_text = """
        Ransomware Simulation & Decryption Tool
        
        This application is designed by Vanessa Baah-Williams for  purposes only to demonstrate how ransomware works and how files can be decrypted.
        
        Features:
        - Simulates ransomware encryption on a test directory
        - Demonstrates secure key generation
        - Provides decryption tools
        - Includes a key recovery module
        
        WARNING: This tool should only be used in controlled environments with test files.
        Never use on important data or production systems.
        
      
        """
        
        text_widget = tk.Text(frame, wrap=tk.WORD, height=20)
        text_widget.pack(fill='both', expand=True)
        text_widget.insert(tk.END, about_text)
        text_widget.config(state=tk.DISABLED)
