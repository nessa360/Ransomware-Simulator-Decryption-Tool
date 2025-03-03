# Ransomware Simulator & Decryption Tool

An educational tool designed to demonstrate encryption/decryption techniques and ransomware behavior in a controlled environment. This application is for educational purposes only and should never be used maliciously.

## Features

- File encryption simulation with customizable target extensions
- Secure key generation and storage
- File decryption capabilities
- Key recovery module
- Modern GUI with tabbed interface

## Requirements

```
cryptography>=41.0.0
tkinter (comes with Python)
```

## Project Structure

- `app.py` - Main application entry point
- `core/` - Core encryption/decryption functionality
  - `simulator.py` - RansomwareSimulator class implementation
  - `crypto.py` - Cryptography-related utilities
- `gui/` - GUI components
  - `main_window.py` - Main GUI window implementation
  - `tabs/` - Individual tab implementations
    - `simulation_tab.py` - Simulation tab
    - `decryption_tab.py` - Decryption tab
    - `recovery_tab.py` - Key recovery tab
    - `about_tab.py` - About tab

## Installation

1. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Run the application:
```bash
python app.py
```

## Warning

This tool should only be used in controlled environments with test files. Never use on important data or production systems.

## Educational Value

- Learn about encryption/decryption techniques
- Understand file system operations
- Study cryptography fundamentals
- Practice secure key management
- Explore ransomware prevention tactics

## License

MIT License - See LICENSE file for details
