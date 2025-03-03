import tkinter as tk
from tkinter import ttk
from core.simulator import RansomwareSimulator
from .tabs.simulation_tab import SimulationTab
from .tabs.decryption_tab import DecryptionTab
from .tabs.recovery_tab import RecoveryTab
from .tabs.about_tab import AboutTab

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
        simulation_tab = SimulationTab(self.notebook, self.simulator)
        decryption_tab = DecryptionTab(self.notebook, self.simulator)
        recovery_tab = RecoveryTab(self.notebook, self.simulator)
        about_tab = AboutTab(self.notebook)
        
        self.notebook.add(simulation_tab, text="Simulation")
        self.notebook.add(decryption_tab, text="Decryption")
        self.notebook.add(recovery_tab, text="Key Recovery")
        self.notebook.add(about_tab, text="About")
