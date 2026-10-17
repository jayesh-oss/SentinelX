# SentinelX

A next-generation antivirus engine for Windows, built in Python. SentinelX layers five independent detection methods on top of each other - signatures, machine learning, deep learning, cloud intelligence, and ransomware behavioural analysis - so that no single engine is a point of failure.

---

## Detection Engines

### 1. YARA Signature Scanning
Over 1,150 compiled YARA rules sourced from the Elastic detection rules repository. Every scanned file is matched against the full ruleset. A single match is treated as a high-confidence indicator and contributes the maximum weight to the threat score.

### 2. Machine Learning - PE Heuristics
A pre-trained Random Forest / XGBoost model analyses eight features extracted from the PE header: section entropy, import count, suspicious API presence, section count, resource size, timestamp anomalies, overlay size, and header checksum validity. The model outputs a probability score that is fed into the unified scoring pipeline alongside the YARA result.

### 3. Visual CNN - Binary Image Classification
The file's raw bytes are rendered as a grayscale image and passed through a fine-tuned EfficientNet-B0 convolutional neural network. This catches obfuscated or packed samples that defeat signature matching - malware families tend to produce visually distinct byte patterns regardless of how the code is encrypted.

### 4. VirusTotal Cloud Intelligence
File MD5 hashes are looked up against the VirusTotal API with local SQLite caching to avoid redundant network calls. Results feed into the scoring model: fewer than 3 vendor detections can override a marginal heuristic positive; 3 or more detections add significant weight toward a malicious verdict.

### 5. PE Static Analysis
A dedicated PE analyser extracts: Import Address Table (IAT) contents, section entropy per-section, anomalous section names, suspicious string patterns, anti-analysis imports (IsDebuggerPresent, NtQueryInformationProcess, etc.), and known packer signatures. The results are shared across the ML engine and the ransomware engine to avoid redundant parsing.

### 6. Anti-Ransomware Detection
Every scanned file goes through a four-layer ransomware-specific analysis pass (when enabled):

| Layer | What it checks |
|-------|---------------|
| Extension | Known ransomware file extensions (.locked, .ryuk, .wncry, .conti, .hive, .lockbit, and 35+ others) |
| Entropy | Shannon entropy of the first 8 KB - encrypted/compressed content scores above 7.2 bits/byte |
| Ransom strings | Scans the first 512 KB for embedded ransom note phrases and VSS deletion commands |
| PE reuse | Reuses the already-parsed PE data to flag crypto APIs (CryptEncrypt, BCryptEncrypt) and anti-recovery imports |

The result appears as a separate section at the bottom of each file's scan output so it never gets mixed up with the primary verdict.

---

## Real-Time Protection

### File System Monitor
A `watchdog` observer watches the directory you configure in Settings. Any new or modified file is automatically sent through the full detection pipeline. A 3-second debounce prevents repeated scans of the same write burst.

### Process Execution Monitor
WMI `Win32_Process` creation events are intercepted at the kernel notification level. When an executable launches outside of `C:\Windows\` and `C:\Program Files\`, SentinelX scans it before it has a chance to run. If the verdict is Malicious, the process is terminated via `psutil` and the binary is quarantined immediately.

### Anti-Ransomware Shield
Runs as a set of background daemon threads - completely separate from the scan pipeline. Three independent tripwires:

- **Canary files** - Honeypot decoys named `!SentinelX_Canary_do_not_delete.txt` are placed in Desktop, Documents, Downloads, Pictures, and Videos. Ransomware encrypts files alphabetically, so it hits these first. Any modification to a canary is an immediate high-confidence trigger.
- **Mass modification counter** - A sliding 60-second window counts modifications to protected file types (.docx, .pdf, .jpg, .mp4, .zip, etc.). If 20 or more modifications occur within the window, the shield triggers.
- **VSS deletion watcher** - A separate WMI thread watches for process launches containing `vssadmin delete shadows`, `bcdedit /set`, `wbadmin delete catalog`, and similar shadow copy destruction commands - a near-universal behaviour in ransomware.

When any tripwire fires, SentinelX identifies the process with the highest disk write rate over a 150ms I/O snapshot, terminates it, and queues an alert that appears in the dashboard banner within 2 seconds.

---

## Quarantine System

Detected files are never deleted. The quarantine process:

1. Calculates the MD5 hash of the original file
2. Renames it to `[MD5]_[OriginalName].isolated` and moves it to the `quarantine/` directory
3. Records the original path, quarantine path, hash, and threat name in SQLite
4. Exposes a one-click restore option in the Quarantine tab if a file turns out to be a false positive

---

## Interface

Built with PySide6. Four tabs:

- **Dashboard** - Live statistics (total scans, threats detected, quarantined items), protection status with a donut chart, engine toggle controls, and the ransomware shield alert banner
- **Scanner** - Drag-and-drop or browse file/folder selection, real-time per-file status updates during scanning, and a full structured results view per file showing every engine's output
- **Quarantine** - Lists all quarantined items with their original paths, lets you restore or permanently delete entries
- **Settings** - VirusTotal API key input, monitor directory selector, and UI theme switcher (Professional Dark, Cyberpunk, Hacker Terminal)

---

## Setup

**Requirements:** Windows 10/11, Python 3.10 or newer, added to your system PATH.

```
git clone https://github.com/jaytiwari05/SentinelX.git
cd SentinelX
```

Double-click **`setup.bat`**. It creates the virtual environment, installs all dependencies from `requirements.txt`, and offers to launch the app immediately.

To run it later: double-click **`run_sentinel.bat`**.

SentinelX requests administrator elevation on launch - required for WMI process monitoring and process termination.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| PySide6 | GUI framework |
| yara-python | YARA rule engine |
| scikit-learn / xgboost | ML heuristic model |
| torch / torchvision | Visual CNN (EfficientNet-B0) |
| pefile | PE header parsing |
| psutil | Process I/O and termination |
| watchdog | File system monitoring |
| pywin32 / WMI | Windows process creation events |
| requests | VirusTotal API calls |
| Pillow | Binary-to-image conversion |
| joblib / numpy / pandas | ML data pipeline |

---

## Architecture

For the internal scoring algorithm, ransomware detection layers, and real-time protection flow diagrams, see [ARCHITECTURE.md](ARCHITECTURE.md).

---

*Built for educational and research purposes. Not a substitute for enterprise endpoint security.*
