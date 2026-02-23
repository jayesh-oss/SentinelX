# SentinelX Antivirus 🛡️

SentinelX is a lightweight, high-performance, and open-source Next-Generation Antivirus (NGAV) engine developed in Python. It blends traditional signature-based detection (via YARA) with modern machine learning heuristics, real-time process monitoring, and cloud intelligence via VirusTotal.

## 🌟 Project Highlights

- **Hybrid Detection Engine**: Utilizes **1,150+ compiled YARA rules** alongside a custom Scikit-Learn/XGBoost Machine Learning model for detecting zero-day anomalies based on Portable Executable (PE) characteristics.
- **Real-Time File Protection**: Powered by `watchdog`, it monitors specified directories on-the-fly, instantly evaluating new or modified files.
- **Process Execution Monitoring**: Hooks into Windows Management Instrumentation (WMI) to silently observe process creation events. If a malicious executable is launched, SentinelX swiftly terminates its process ID and isolates the binary.
- **Cloud Intelligence**: Integrates the **VirusTotal API** for expanded threat intelligence and reputation scoring.
- **Secure Quarantine System**: Automatically isolates detected threats into a secure vault, encrypting or renaming them to prevent accidental execution, while maintaining a database ledger for easy restoration or permanent deletion.
- **Modern & Dynamic UI**: Built with PySide6, featuring an interactive dashboard, live donut charts, and multiple aesthetically pleasing themes (e.g., Cyberpunk, Professional Dark, Hacker Terminal).

---

## 🚀 Quick Setup (Windows)

To get SentinelX running on any Windows machine within minutes, we have provided automated setup scripts.

**Prerequisites:**
- Python 3.9 or higher installed and added to your system `PATH`.
- Git (optional, for cloning).

**Installation:**
1. Clone the repository or download the source code:
   ```cmd
   git clone https://github.com/jaytiwari05/SentinelX.git
   cd SentinelX
   ```
2. Double-click **`setup.bat`**.
   *This script automatically creates a Python Virtual Environment (`venv`), upgrades `pip`, and installs all dependencies from `requirements.txt` quietly in the background.*
3. When prompted, type `Y` to launch SentinelX immediately.

**To run the app later:**
Simply double-click **`run_sentinel.bat`**.

---

## 🛠️ Configuration & Customization

- **API Keys**: SentinelX requires a free VirusTotal API key to fetch cloud reports. You can input this safely inside the `Settings` tab within the application.
- **Target Directories**: The Real-Time Watchdog feature allows you to browse and select any specific directory to monitor dynamically.

## 📚 Technical Architecture & Flow

For a deep dive into how the underlying Core Scanner evaluates threats, and a detailed logic flow chart of the Behavioral and Process Monitors, please refer to the [**ARCHITECTURE.md**](ARCHITECTURE.md) document.

---

*Disclaimer: This project was developed for educational and experimental purposes. Do not rely entirely on this software for enterprise production security without further rigorous auditing.*
